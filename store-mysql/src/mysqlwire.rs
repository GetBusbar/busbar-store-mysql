// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MYSQL CLIENT PROTOCOL OVER THE HOST'S CONNECTOR: the 1.5.5 `mysql` driver's connection logic
//! (`mysql` 26, the `minimal` build the store shipped with), every byte through the op's one
//! connection ([`Wire`], the store SDK's `wire`), so this store opens no socket of its own (busbar
//! THE DESIGN, the connections section; ARCHITECT rulings 2026-10-03 on Q-L14-1 / Q-L16-2).
//!
//! The protocol itself is `mysql_common` 0.35.5, the sans-IO core that driver is built on: the
//! packet codec (plain and compressed), the v10 handshake, `mysql_native_password` and
//! `caching_sha2_password` (its RSA full authentication included), `COM_QUERY` (text rows),
//! `COM_STMT_PREPARE`/`COM_STMT_EXECUTE` (binary rows), and `Value`/`Row`/`FromRow`/`params!`. So
//! every parameter and column converts exactly as it did over the driver.
//!
//! The surface mirrors the driver's (`Opts::from_url`, `query*`/`exec*`, `Transaction`,
//! `affected_rows`, `last_insert_id`, `Error` with its `Display`) with every call `async`, so the
//! store's SQL bodies are the 1.5.5 bodies with `.await`. What the driver's pool did around each
//! checkout is kept too (`MysqlStore`'s kept set): a kept connection is pinged before it is used
//! (`check_health`) and reset when it comes back (`COM_RESET_CONNECTION` and the store's `init`
//! statements again, `reset_connection`), and a `Transaction` dropped without `commit` is rolled
//! back before the connection's next statement, as the driver's was.
//!
//! TLS: the 1.5.5 build had none (its `minimal` features compile no TLS stack, and its URL names no
//! TLS parameter), so neither does this; a URL naming one is refused as it was.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::BytesMut;
use mysql_common::constants::{
    CapabilityFlags, Command, StatusFlags, DEFAULT_MAX_ALLOWED_PACKET, MAX_PAYLOAD_LEN,
};
use mysql_common::io::{ParseBuf, ReadMysqlExt};
use mysql_common::named_params::ParsedNamedParams;
use mysql_common::packets::{
    AuthPlugin, AuthSwitchRequest, Column, ComStmtClose, ComStmtExecuteRequestBuilder,
    ComStmtSendLongData, CommonOkPacket, ErrPacket, HandshakePacket, HandshakeResponse, OkPacket,
    OkPacketDeserializer, OkPacketKind, OldAuthSwitchRequest, OldEofPacket, ResultSetTerminator,
    StmtPacket,
};
use mysql_common::proto::codec::{Compression, PacketCodec};
use mysql_common::proto::{Binary, MySerialize, Text};
use mysql_common::row::convert::{from_row, FromRow};
use mysql_common::row::RowDeserializer;
use mysql_common::value::ServerSide;

pub use mysql_common::params::Params;
pub use mysql_common::row::Row;
pub use mysql_common::value::Value;

use busbar_contract::abi::sdk::store::wire::Wire;

// ── errors (the driver's, in its words) ─────────────────────────────────────────────────────────

/// A server-side failure (an ERR packet).
#[derive(Eq, PartialEq, Clone)]
pub struct MySqlError {
    pub state: String,
    pub message: String,
    pub code: u16,
}

impl fmt::Display for MySqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ERROR {} ({}): {}", self.code, self.state, self.message)
    }
}

impl fmt::Debug for MySqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'a> From<mysql_common::packets::ServerError<'a>> for MySqlError {
    fn from(x: mysql_common::packets::ServerError<'a>) -> MySqlError {
        MySqlError {
            state: x
                .sql_state_ref()
                .map(|x| x.as_str().as_ref().to_owned())
                .unwrap_or_else(|| "HY000".to_owned()),
            code: x.error_code(),
            message: x.message_str().into_owned(),
        }
    }
}

/// The driver's own refusals.
#[derive(Eq, PartialEq, Clone)]
pub enum DriverError {
    /// `(address, description)`: the host's connector could not reach the server.
    CouldNotConnect(Option<(String, String)>),
    UnsupportedProtocol(u8),
    Protocol41NotSet,
    UnexpectedPacket,
    MismatchedStmtParams(u16, usize),
    SetupError,
    MissingNamedParameter(String),
    NamedParamsForPositionalQuery,
    MixedParams,
    UnknownAuthPlugin(String),
    OldMysqlPasswordDisabled,
    CleartextPluginDisabled,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::CouldNotConnect(None) => {
                write!(f, "Could not connect: address not specified")
            }
            DriverError::CouldNotConnect(Some((addr, desc))) => {
                write!(f, "Could not connect to address `{addr}': {desc}")
            }
            DriverError::UnsupportedProtocol(v) => write!(f, "Unsupported protocol version {v}"),
            DriverError::Protocol41NotSet => write!(f, "Server must set CLIENT_PROTOCOL_41 flag"),
            DriverError::UnexpectedPacket => write!(f, "Unexpected packet"),
            DriverError::MismatchedStmtParams(exp, prov) => write!(
                f,
                "Statement takes {exp} parameters but {prov} was supplied"
            ),
            DriverError::SetupError => write!(f, "Could not setup connection"),
            DriverError::MissingNamedParameter(name) => {
                write!(f, "Missing named parameter `{name}' for statement")
            }
            DriverError::NamedParamsForPositionalQuery => {
                write!(f, "Can not pass named parameters to positional query")
            }
            DriverError::MixedParams => write!(
                f,
                "Can not mix named and positional parameters in one statement"
            ),
            DriverError::UnknownAuthPlugin(name) => {
                write!(f, "Unknown authentication protocol: `{name}`")
            }
            DriverError::OldMysqlPasswordDisabled => write!(
                f,
                "`old_mysql_password` plugin is insecure and disabled by default",
            ),
            DriverError::CleartextPluginDisabled => {
                write!(f, "mysql_clear_password must be enabled on the client side")
            }
        }
    }
}

impl fmt::Debug for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A connection URL the driver does not accept.
#[derive(Eq, PartialEq, Clone)]
pub enum UrlError {
    ParseError(url::ParseError),
    UnsupportedScheme(String),
    InvalidValue(String, String),
    UnknownParameter(String),
    InvalidPoolConstraints { min: usize, max: usize },
    BadUrl,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlError::ParseError(err) => write!(f, "URL ParseError {{ {err} }}"),
            UrlError::UnsupportedScheme(s) => write!(f, "URL scheme `{s}' is not supported"),
            UrlError::InvalidValue(parameter, value) => {
                write!(f, "Invalid value `{value}' for URL parameter `{parameter}'")
            }
            UrlError::UnknownParameter(parameter) => {
                write!(f, "Unknown URL parameter `{parameter}'")
            }
            UrlError::InvalidPoolConstraints { min, max } => write!(
                f,
                "Invalid pool constraints: pool_min ({min}) > pool_max ({max})"
            ),
            UrlError::BadUrl => write!(f, "Invalid or incomplete connection URL"),
        }
    }
}

impl fmt::Debug for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<url::ParseError> for UrlError {
    fn from(x: url::ParseError) -> UrlError {
        UrlError::ParseError(x)
    }
}

/// A driver error, in the `mysql` crate's words (its variant names, which callers match on).
#[allow(clippy::enum_variant_names)]
pub enum Error {
    IoError(String),
    CodecError(mysql_common::proto::codec::error::PacketCodecError),
    MySqlError(MySqlError),
    DriverError(DriverError),
}

impl Error {
    fn server_disconnected() -> Self {
        Error::IoError("server disconnected".into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IoError(err) => write!(f, "IoError {{ {err} }}"),
            Error::CodecError(err) => write!(f, "CodecError {{ {err} }}"),
            Error::MySqlError(err) => write!(f, "MySqlError {{ {err} }}"),
            Error::DriverError(err) => write!(f, "DriverError {{ {err} }}"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e.to_string())
    }
}

impl From<DriverError> for Error {
    fn from(e: DriverError) -> Self {
        Error::DriverError(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ── the connection URL (the driver's `Opts::from_url`) ──────────────────────────────────────────

/// The driver's default pool constraints, which `pool_min`/`pool_max` are validated against.
const POOL_MIN_DEFAULT: usize = 10;
const POOL_MAX_DEFAULT: usize = 100;
/// The driver's per-connection prepared-statement cache.
const STMT_CACHE_DEFAULT: usize = 32;

/// What a `mysql://` URL says (the parts a connection over the host's connector uses; the TCP
/// socket options the driver accepted are accepted and validated alike, and served by the host).
#[derive(Clone, PartialEq, Eq)]
pub struct Opts {
    pub user: Option<String>,
    pub pass: Option<String>,
    pub host: url::Host,
    pub port: u16,
    pub db_name: Option<String>,
    /// A unix-socket path (`socket=`): the connection goes there instead of `host:port`.
    pub socket: Option<String>,
    pub compress: bool,
    pub tcp_connect_timeout_ms: Option<u64>,
    pub max_allowed_packet: Option<usize>,
    pub secure_auth: bool,
    pub enable_cleartext_plugin: bool,
    pub stmt_cache_size: usize,
}

impl fmt::Debug for Opts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opts")
            .field("user", &self.user)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("db_name", &self.db_name)
            .finish_non_exhaustive()
    }
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode(s.as_bytes())
        .decode_utf8_lossy()
        .into_owned()
}

impl Opts {
    /// Parse a `mysql://user:pass@host:port/db?key=value&...` URL exactly as the driver did: the
    /// same accepted parameters, the same validation, the same refusal texts.
    ///
    /// # Errors
    /// The driver's [`UrlError`].
    pub fn from_url(url_str: &str) -> Result<Opts, UrlError> {
        let url = url::Url::parse(url_str)?;
        if url.scheme() != "mysql" {
            return Err(UrlError::UnsupportedScheme(url.scheme().to_string()));
        }
        if url.cannot_be_a_base() {
            return Err(UrlError::BadUrl);
        }
        let user = Some(url.username()).filter(|u| !u.is_empty()).map(decode);
        let pass = url.password().map(decode);
        let host = url
            .host()
            .ok_or(UrlError::BadUrl)
            .and_then(|host| url::Host::parse(&host.to_string()).map_err(|_| UrlError::BadUrl))?;
        let port = url.port().unwrap_or(3306);
        let db_name = url
            .path_segments()
            .and_then(|mut s| s.next().filter(|d| !d.is_empty()).map(decode));
        let mut opts = Opts {
            user,
            pass,
            host,
            port,
            db_name,
            socket: None,
            compress: false,
            tcp_connect_timeout_ms: None,
            max_allowed_packet: None,
            secure_auth: true,
            enable_cleartext_plugin: false,
            stmt_cache_size: STMT_CACHE_DEFAULT,
        };
        let pairs: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let mut pool_min = POOL_MIN_DEFAULT;
        let mut pool_max = POOL_MAX_DEFAULT;
        for (key, value) in &pairs {
            let invalid = || UrlError::InvalidValue(key.to_string(), value.to_string());
            match key.as_str() {
                "pool_min" => pool_min = value.parse().map_err(|_| invalid())?,
                "pool_max" => pool_max = value.parse().map_err(|_| invalid())?,
                "user" => opts.user = Some(value.to_string()),
                "password" => opts.pass = Some(value.to_string()),
                "host" => {
                    opts.host = url::Host::parse(value)
                        .unwrap_or_else(|_| url::Host::Domain(value.to_owned()));
                }
                "port" => opts.port = value.parse().map_err(|_| invalid())?,
                "socket" => opts.socket = Some(value.to_string()),
                "db_name" => opts.db_name = Some(value.to_string()),
                // Accepted as the driver accepted them; the connection is the host's (its
                // connector owns the socket's options and the transport it dials).
                "prefer_socket" | "reset_connection" | "check_health" => {
                    value.parse::<bool>().map_err(|_| invalid())?;
                }
                "enable_cleartext_plugin" => {
                    opts.enable_cleartext_plugin = value.parse().map_err(|_| invalid())?;
                }
                "secure_auth" => opts.secure_auth = value.parse().map_err(|_| invalid())?,
                "tcp_keepalive_time_ms" => {
                    value.parse::<u32>().map_err(|_| invalid())?;
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                "tcp_keepalive_probe_interval_secs" | "tcp_keepalive_probe_count" => {
                    value.parse::<u32>().map_err(|_| invalid())?;
                }
                #[cfg(target_os = "linux")]
                "tcp_user_timeout_ms" => {
                    value.parse::<u32>().map_err(|_| invalid())?;
                }
                "compress" => match value.parse::<u32>() {
                    Ok(_) => opts.compress = true,
                    Err(_) => match value.as_str() {
                        "fast" | "best" | "true" => opts.compress = true,
                        _ => return Err(invalid()),
                    },
                },
                "tcp_connect_timeout_ms" => {
                    opts.tcp_connect_timeout_ms = Some(value.parse().map_err(|_| invalid())?);
                }
                "stmt_cache_size" => opts.stmt_cache_size = value.parse().map_err(|_| invalid())?,
                "max_allowed_packet" => {
                    opts.max_allowed_packet = Some(value.parse().map_err(|_| invalid())?);
                }
                _ => return Err(UrlError::UnknownParameter(key.to_string())),
            }
        }
        if pool_min > pool_max {
            return Err(UrlError::InvalidPoolConstraints {
                min: pool_min,
                max: pool_max,
            });
        }
        Ok(opts)
    }

    /// The host as the driver dialled it (an IPv6 address unbracketed).
    fn host_name(&self) -> String {
        match &self.host {
            url::Host::Domain(d) => d.clone(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        }
    }

    /// The target the store's need dials on the host's connector: `host:port`, or `unix:<path>`.
    #[must_use]
    pub fn target(&self) -> String {
        if let Some(socket) = &self.socket {
            return format!("unix:{socket}");
        }
        match &self.host {
            url::Host::Ipv6(ip) => format!("[{ip}]:{}", self.port),
            _ => format!("{}:{}", self.host_name(), self.port),
        }
    }

    /// The address a failed connect names, as the driver named it.
    fn address(&self) -> String {
        match &self.socket {
            Some(socket) => socket.clone(),
            None => format!("{}:{}", self.host_name(), self.port),
        }
    }
}

// ── the transport ───────────────────────────────────────────────────────────────────────────────

/// Where a connection's bytes go: the op's wire (the host's connector), or, in this crate's own
/// tests only, a plain TCP stream to the live server (the internals' tests drive the client
/// directly; nothing here is in the shipped image).
pub(crate) enum Io {
    Wire(Wire),
    #[cfg(test)]
    Tcp(std::net::TcpStream),
}

impl Io {
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Io::Wire(w) => w.write_all(bytes).await.map_err(|e| e.to_string()),
            #[cfg(test)]
            Io::Tcp(s) => std::io::Write::write_all(s, bytes).map_err(|e| e.to_string()),
        }
    }

    /// Read more bytes onto `into`: how many (`0` = the server closed the connection).
    async fn fill(&mut self, into: &mut BytesMut) -> Result<usize, String> {
        match self {
            Io::Wire(w) => {
                let n = w.fill().await.map_err(|e| e.to_string())?;
                w.input(|i| {
                    into.extend_from_slice(i);
                    i.clear();
                });
                Ok(n)
            }
            #[cfg(test)]
            Io::Tcp(s) => {
                let mut buf = [0_u8; 16 * 1024];
                let n = std::io::Read::read(s, &mut buf).map_err(|e| e.to_string())?;
                into.extend_from_slice(&buf[..n]);
                Ok(n)
            }
        }
    }

    fn wire(&self) -> Option<&Wire> {
        match self {
            Io::Wire(w) => Some(w),
            #[cfg(test)]
            Io::Tcp(_) => None,
        }
    }
}

// ── the connection ──────────────────────────────────────────────────────────────────────────────

/// A prepared statement, as the connection's cache keeps it.
struct Stmt {
    id: u32,
    num_params: u16,
}

/// What a connection carries across the ops that reuse it (the store SDK's kept set keeps it with
/// the connection, [`Wire::set_session`]).
struct State {
    opts: Arc<Opts>,
    codec: PacketCodec,
    inbuf: BytesMut,
    caps: CapabilityFlags,
    status: StatusFlags,
    server_version: Option<(u16, u16, u16)>,
    mariadb_version: Option<(u16, u16, u16)>,
    connection_id: u32,
    nonce: Vec<u8>,
    auth_plugin: AuthPlugin<'static>,
    /// Prepared statements by their (positional) query text.
    stmts: HashMap<Vec<u8>, Arc<Stmt>>,
    /// The last OK packet (affected rows, last insert id).
    ok: Option<OkPacket<'static>>,
    has_results: bool,
    /// The connection is a unix socket (the driver sent a cleartext password over one).
    socket: bool,
}

/// The kept-connection session ([`Wire::set_session`] needs `Clone`).
type Kept = Arc<Mutex<Option<State>>>;

/// One result set's shape.
enum Meta {
    Empty,
    Rows(Arc<[Column]>),
}

/// What an `exec_iter` answered: the rows it affected.
pub struct Affected(u64);

impl Affected {
    #[must_use]
    pub fn affected_rows(&self) -> u64 {
        self.0
    }
}

/// ONE CONNECTION TO THE SERVER over the op's transport. It is KEPT for the instance's next op
/// only when [`Conn::release`] resets it cleanly; dropped any other way (an early return, a
/// protocol failure), it is discarded and the next op dials fresh.
pub struct Conn {
    io: Io,
    st: State,
    /// A `Transaction` was dropped uncommitted: roll it back before the next statement.
    rollback_pending: bool,
    /// The byte stream failed (an I/O or codec error): never kept.
    broken: bool,
    /// [`Conn::release`] reset it: keep it.
    keep: bool,
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.keep {
            if let Some(w) = self.io.wire() {
                w.discard();
            }
        }
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("connection_id", &self.st.connection_id)
            .finish_non_exhaustive()
    }
}

/// The connect attributes the 1.5.5 driver sent (`performance_schema.session_connect_attrs`).
fn connect_attrs() -> HashMap<String, String> {
    let program_name = std::env::args_os()
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut attrs = HashMap::new();
    attrs.insert("_client_name".into(), "rust-mysql-simple".into());
    attrs.insert("_client_version".into(), "26.0.1".into());
    attrs.insert("_os".into(), std::env::consts::OS.into());
    attrs.insert("_pid".into(), std::process::id().to_string());
    attrs.insert("_platform".into(), std::env::consts::ARCH.into());
    attrs.insert("program_name".into(), program_name);
    attrs
}

fn io_err(e: std::io::Error) -> Error {
    Error::IoError(e.to_string())
}

impl State {
    fn new(opts: Arc<Opts>) -> Self {
        let socket = opts.socket.is_some();
        State {
            opts,
            codec: PacketCodec::default(),
            inbuf: BytesMut::new(),
            caps: CapabilityFlags::empty(),
            status: StatusFlags::empty(),
            server_version: None,
            mariadb_version: None,
            connection_id: 0,
            nonce: Vec::new(),
            auth_plugin: AuthPlugin::MysqlNativePassword,
            stmts: HashMap::new(),
            ok: None,
            has_results: false,
            socket,
        }
    }
}

/// An auth step that may switch plugins and continue (the one recursive path).
type AuthStep<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

impl Conn {
    fn new(io: Io, opts: Arc<Opts>) -> Self {
        Conn {
            io,
            st: State::new(opts),
            rollback_pending: false,
            broken: false,
            keep: false,
        }
    }

    /// THE OP'S CONNECTION over `wire` (need `need`, the target the URL names): the kept one when
    /// it is idle and answers a ping (the driver pool's `check_health`), else a fresh dial, its
    /// handshake, authentication, `max_allowed_packet` and the `init` statements, exactly as the
    /// driver's `Conn::new` ran them.
    ///
    /// # Errors
    /// The connector's failure (as the driver's connect failure), or the server's refusal.
    pub async fn open(wire: Wire, opts: &Arc<Opts>, need: u32, init: &[&str]) -> Result<Conn> {
        let timeout = opts
            .tcp_connect_timeout_ms
            .map_or(0, |ms| u32::try_from(ms).unwrap_or(u32::MAX));
        let could_not = |e: busbar_contract::abi::sdk::conn::ConnFailure| {
            Error::DriverError(DriverError::CouldNotConnect(Some((
                opts.address(),
                e.to_string(),
            ))))
        };
        wire.connect_timed(need, Some(&opts.target()), timeout)
            .await
            .map_err(could_not)?;
        if wire.reused() {
            let kept = wire
                .session::<Kept>()
                .and_then(|k| k.lock().unwrap_or_else(PoisonError::into_inner).take());
            if let Some(st) = kept {
                let mut c = Conn {
                    io: Io::Wire(wire.clone()),
                    st,
                    rollback_pending: false,
                    broken: false,
                    keep: false,
                };
                if c.ping().await.is_ok() {
                    return Ok(c);
                }
                // A dead kept connection: the driver's pool dropped it and dialled again.
                drop(c);
            }
            wire.reconnect().await.map_err(could_not)?;
        }
        let mut c = Conn::new(Io::Wire(wire), opts.clone());
        c.handshake(init).await?;
        Ok(c)
    }

    /// A connection over a plain TCP stream to the live server (this crate's tests only).
    #[cfg(test)]
    pub(crate) async fn open_tcp(opts: &Arc<Opts>, init: &[&str]) -> Result<Conn> {
        let s = std::net::TcpStream::connect(opts.target()).map_err(|e| {
            Error::DriverError(DriverError::CouldNotConnect(Some((
                opts.address(),
                e.to_string(),
            ))))
        })?;
        let _ = s.set_nodelay(true);
        let mut c = Conn::new(Io::Tcp(s), opts.clone());
        c.handshake(init).await?;
        Ok(c)
    }

    /// The op is done with the connection: reset it for the next op (the driver pool's
    /// `reset_connection`: `COM_RESET_CONNECTION`, then the `init` statements again) and keep it;
    /// a connection whose stream failed, or that does not reset, is discarded.
    pub async fn release(mut self, init: &[&str]) {
        if self.broken || !self.st.inbuf.is_empty() || self.st.has_results {
            return;
        }
        let reset = match (self.st.server_version, self.st.mariadb_version) {
            (Some(v), _) if v > (5, 7, 3) => true,
            (_, Some(v)) if v >= (10, 2, 7) => true,
            _ => false,
        };
        // A server without COM_RESET_CONNECTION (the driver fell back to COM_CHANGE_USER): a
        // fresh connection is the same clean session.
        if !reset || self.reset(init).await.is_err() {
            return;
        }
        let Some(wire) = self.io.wire().cloned() else {
            return;
        };
        let fresh = State::new(self.st.opts.clone());
        let st = std::mem::replace(&mut self.st, fresh);
        wire.set_session::<Kept>(Arc::new(Mutex::new(Some(st))));
        self.keep = true;
    }

    async fn reset(&mut self, init: &[&str]) -> Result<()> {
        self.write_command(Command::COM_RESET_CONNECTION, &[])
            .await?;
        let packet = self.read_packet().await?;
        self.handle_ok::<CommonOkPacket>(&packet)?;
        self.st.stmts.clear();
        self.rollback_pending = false;
        for cmd in init {
            self.query_drop(cmd).await?;
        }
        Ok(())
    }

    // ── packets ────────────────────────────────────────────────────────────────────────────────

    async fn raw_read(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        loop {
            match self.st.codec.decode(&mut self.st.inbuf, buf) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => {
                    self.broken = true;
                    return Err(Error::CodecError(e));
                }
            }
            match self.io.fill(&mut self.st.inbuf).await {
                Ok(0) => {
                    self.broken = true;
                    return Err(Error::server_disconnected());
                }
                Ok(_) => {}
                Err(e) => {
                    self.broken = true;
                    return Err(Error::IoError(e));
                }
            }
        }
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let mut buffer = Vec::new();
            match self.raw_read(&mut buffer).await {
                Ok(()) if buffer.first() == Some(&0xff) => {
                    match ParseBuf(&buffer)
                        .parse::<ErrPacket<'_>>(self.st.caps)
                        .map_err(io_err)?
                    {
                        ErrPacket::Error(server_error) => {
                            self.handle_err();
                            return Err(Error::MySqlError(MySqlError::from(server_error)));
                        }
                        ErrPacket::Progress(_) => continue,
                    }
                }
                Ok(()) => return Ok(buffer),
                Err(e) => {
                    self.handle_err();
                    return Err(e);
                }
            }
        }
    }

    async fn drop_packet(&mut self) -> Result<()> {
        self.read_packet().await.map(drop)
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut out = BytesMut::new();
        if let Err(e) = self.st.codec.encode(&mut &payload[..], &mut out) {
            self.broken = true;
            return Err(Error::CodecError(e));
        }
        if let Err(e) = self.io.write_all(&out).await {
            self.broken = true;
            return Err(Error::IoError(e));
        }
        Ok(())
    }

    async fn write_struct<T: MySerialize>(&mut self, s: &T) -> Result<()> {
        let mut buf = Vec::new();
        s.serialize(&mut buf);
        self.write_packet(&buf).await
    }

    async fn write_command_raw<T: MySerialize>(&mut self, cmd: &T) -> Result<()> {
        let mut buf = Vec::new();
        cmd.serialize(&mut buf);
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await
    }

    async fn write_command(&mut self, cmd: Command, data: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(cmd as u8);
        buf.extend_from_slice(data);
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await
    }

    fn handle_ok<T: OkPacketKind>(&mut self, buffer: &[u8]) -> Result<()> {
        let ok = ParseBuf(buffer)
            .parse::<OkPacketDeserializer<T>>(self.st.caps)
            .map_err(io_err)?
            .into_inner();
        self.st.status = ok.status_flags();
        self.st.ok = Some(ok.into_owned());
        Ok(())
    }

    fn handle_err(&mut self) {
        self.st.status = StatusFlags::empty();
        self.st.has_results = false;
        self.st.ok = None;
    }

    fn more_results_exists(&self) -> bool {
        self.st
            .status
            .contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS)
    }

    fn has_capability(&self, flag: CapabilityFlags) -> bool {
        self.st.caps.contains(flag)
    }

    // ── the handshake ──────────────────────────────────────────────────────────────────────────

    fn client_flags(&self) -> CapabilityFlags {
        let mut flags = CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_SECURE_CONNECTION
            | CapabilityFlags::CLIENT_LONG_PASSWORD
            | CapabilityFlags::CLIENT_TRANSACTIONS
            | CapabilityFlags::CLIENT_LOCAL_FILES
            | CapabilityFlags::CLIENT_MULTI_STATEMENTS
            | CapabilityFlags::CLIENT_MULTI_RESULTS
            | CapabilityFlags::CLIENT_PS_MULTI_RESULTS
            | CapabilityFlags::CLIENT_PLUGIN_AUTH
            | CapabilityFlags::CLIENT_CONNECT_ATTRS
            | (self.st.caps & CapabilityFlags::CLIENT_LONG_FLAG);
        if self.st.opts.compress {
            flags.insert(CapabilityFlags::CLIENT_COMPRESS);
        }
        if self
            .st
            .opts
            .db_name
            .as_deref()
            .is_some_and(|d| !d.is_empty())
        {
            flags.insert(CapabilityFlags::CLIENT_CONNECT_WITH_DB);
        }
        flags
    }

    async fn handshake(&mut self, init: &[&str]) -> Result<()> {
        let payload = self.read_packet().await?;
        let handshake = ParseBuf(&payload)
            .parse::<HandshakePacket<'_>>(())
            .map_err(io_err)?;
        if handshake.protocol_version() != 10 {
            return Err(DriverError::UnsupportedProtocol(handshake.protocol_version()).into());
        }
        if !handshake
            .capabilities()
            .contains(CapabilityFlags::CLIENT_PROTOCOL_41)
        {
            return Err(DriverError::Protocol41NotSet.into());
        }
        self.st.caps = handshake.capabilities() & self.client_flags();
        self.st.status = handshake.status_flags();
        self.st.connection_id = handshake.connection_id();
        self.st.server_version = handshake.server_version_parsed();
        self.st.mariadb_version = handshake.maria_db_server_version_parsed();
        // The scramble is 20 bytes (21 with its terminator), zero-filled if shorter.
        let mut nonce = Vec::from(handshake.scramble_1_ref());
        nonce.extend_from_slice(handshake.scramble_2_ref().unwrap_or(&[][..]));
        nonce.resize(20, 0);
        self.st.nonce = nonce;
        self.st.auth_plugin = match handshake.auth_plugin() {
            Some(x @ AuthPlugin::CachingSha2Password) => x.into_owned(),
            _ => AuthPlugin::MysqlNativePassword,
        };
        drop(payload);
        self.write_handshake_response().await?;
        self.continue_auth(false).await?;
        if self.has_capability(CapabilityFlags::CLIENT_COMPRESS) {
            self.st.codec.compress(Compression::default());
        }
        let max_allowed_packet = match self.st.opts.max_allowed_packet {
            Some(x) => x,
            None => {
                let v: Option<Row> = self.query_first("SELECT @@max_allowed_packet").await?;
                v.and_then(|mut r| r.take_opt::<usize, _>(0))
                    .and_then(std::result::Result::ok)
                    .unwrap_or(0)
            }
        };
        if max_allowed_packet == 0 {
            return Err(DriverError::SetupError.into());
        }
        self.st.codec.max_allowed_packet = max_allowed_packet;
        for cmd in init {
            self.query_drop(cmd).await?;
        }
        Ok(())
    }

    async fn write_handshake_response(&mut self) -> Result<()> {
        let pass = self.st.opts.pass.clone();
        let auth_data = self
            .st
            .auth_plugin
            .gen_data(pass.as_deref(), &self.st.nonce)
            .map(|x| x.into_owned());
        let user = self.st.opts.user.clone();
        let db = self.st.opts.db_name.clone();
        let response = HandshakeResponse::new(
            auth_data.as_deref(),
            self.st.server_version.unwrap_or((0, 0, 0)),
            user.as_deref().map(str::as_bytes),
            db.as_deref().map(str::as_bytes),
            Some(self.st.auth_plugin.clone()),
            self.st.caps,
            Some(connect_attrs()),
            self.st
                .opts
                .max_allowed_packet
                .unwrap_or(DEFAULT_MAX_ALLOWED_PACKET) as u32,
        );
        let mut buf = Vec::new();
        response.serialize(&mut buf);
        self.write_packet(&buf).await
    }

    fn continue_auth(&mut self, auth_switched: bool) -> AuthStep<'_> {
        Box::pin(self.continue_auth_inner(auth_switched))
    }

    async fn continue_auth_inner(&mut self, auth_switched: bool) -> Result<()> {
        match self.st.auth_plugin {
            AuthPlugin::CachingSha2Password => self.continue_caching_sha2(auth_switched).await,
            AuthPlugin::MysqlNativePassword | AuthPlugin::MysqlOldPassword => {
                self.continue_native(auth_switched).await
            }
            AuthPlugin::MysqlClearPassword => {
                if !self.st.opts.enable_cleartext_plugin {
                    return Err(DriverError::CleartextPluginDisabled.into());
                }
                self.continue_native(auth_switched).await
            }
            AuthPlugin::Ed25519 => {
                let payload = self.read_packet().await?;
                match payload[0] {
                    0x00 => Ok(()),
                    0xfe if !auth_switched => {
                        let req = ParseBuf(&payload)
                            .parse::<AuthSwitchRequest<'_>>(())
                            .map_err(io_err)?
                            .into_owned();
                        self.auth_switch(req).await
                    }
                    _ => Err(DriverError::UnexpectedPacket.into()),
                }
            }
            AuthPlugin::Other(ref name) => {
                Err(DriverError::UnknownAuthPlugin(String::from_utf8_lossy(name).into()).into())
            }
        }
    }

    async fn continue_native(&mut self, auth_switched: bool) -> Result<()> {
        let payload = self.read_packet().await?;
        match payload[0] {
            0x00 => self.handle_ok::<CommonOkPacket>(&payload),
            0xfe if !auth_switched => {
                let req = if payload.len() > 1 {
                    ParseBuf(&payload)
                        .parse::<AuthSwitchRequest<'_>>(())
                        .map_err(io_err)?
                        .into_owned()
                } else {
                    let _ = ParseBuf(&payload)
                        .parse::<OldAuthSwitchRequest>(())
                        .map_err(io_err)?;
                    AuthSwitchRequest::new("mysql_old_password".as_bytes(), &*self.st.nonce)
                        .into_owned()
                };
                self.auth_switch(req).await
            }
            _ => Err(DriverError::UnexpectedPacket.into()),
        }
    }

    async fn continue_caching_sha2(&mut self, auth_switched: bool) -> Result<()> {
        let payload = self.read_packet().await?;
        match payload[0] {
            // OK for an empty password.
            0x00 => Ok(()),
            0x01 => match payload.get(1) {
                // Fast authentication succeeded.
                Some(0x03) => {
                    let payload = self.read_packet().await?;
                    self.handle_ok::<CommonOkPacket>(&payload)
                }
                // Full authentication: the password in clear over a socket, else RSA-encrypted
                // with the server's public key (this connection is never TLS).
                Some(0x04) => {
                    let mut pass = self
                        .st
                        .opts
                        .pass
                        .as_deref()
                        .map(|p| p.as_bytes().to_vec())
                        .unwrap_or_default();
                    pass.push(0);
                    if self.st.socket {
                        self.write_packet(&pass).await?;
                    } else {
                        self.write_packet(&[0x02]).await?;
                        let payload = self.read_packet().await?;
                        let key = &payload[1..];
                        for (i, c) in pass.iter_mut().enumerate() {
                            *c ^= self.st.nonce[i % self.st.nonce.len()];
                        }
                        let encrypted = mysql_common::crypto::encrypt(&pass, key);
                        self.write_packet(&encrypted).await?;
                    }
                    let payload = self.read_packet().await?;
                    self.handle_ok::<CommonOkPacket>(&payload)
                }
                _ => Err(DriverError::UnexpectedPacket.into()),
            },
            0xfe if !auth_switched => {
                let req = ParseBuf(&payload)
                    .parse::<AuthSwitchRequest<'_>>(())
                    .map_err(io_err)?
                    .into_owned();
                self.auth_switch(req).await
            }
            _ => Err(DriverError::UnexpectedPacket.into()),
        }
    }

    async fn auth_switch(&mut self, req: AuthSwitchRequest<'static>) -> Result<()> {
        if matches!(req.auth_plugin(), AuthPlugin::MysqlOldPassword) && self.st.opts.secure_auth {
            return Err(DriverError::OldMysqlPasswordDisabled.into());
        }
        if matches!(
            req.auth_plugin(),
            AuthPlugin::Other(Cow::Borrowed(b"mysql_clear_password"))
        ) && !self.st.opts.enable_cleartext_plugin
        {
            return Err(DriverError::CleartextPluginDisabled.into());
        }
        self.st.nonce = req.plugin_data().to_vec();
        self.st.auth_plugin = req.auth_plugin().into_owned();
        let pass = self.st.opts.pass.clone();
        let data = match self.st.auth_plugin {
            AuthPlugin::MysqlOldPassword => {
                if self.st.opts.secure_auth {
                    return Err(DriverError::OldMysqlPasswordDisabled.into());
                }
                self.st
                    .auth_plugin
                    .gen_data(pass.as_deref(), &self.st.nonce)
            }
            AuthPlugin::MysqlClearPassword => {
                if !self.st.opts.enable_cleartext_plugin {
                    return Err(
                        DriverError::UnknownAuthPlugin("mysql_clear_password".into()).into(),
                    );
                }
                self.st
                    .auth_plugin
                    .gen_data(pass.as_deref(), &self.st.nonce)
            }
            AuthPlugin::Other(_) => None,
            _ => self
                .st
                .auth_plugin
                .gen_data(pass.as_deref(), &self.st.nonce),
        }
        .map(|d| d.into_owned());
        match data {
            Some(d) => self.write_struct(&d).await?,
            None => self.write_packet(&[]).await?,
        }
        self.continue_auth(true).await
    }

    // ── result sets ────────────────────────────────────────────────────────────────────────────

    async fn handle_result_set(&mut self) -> Result<Meta> {
        if self.more_results_exists() {
            self.st.codec.sync_seq_id();
        }
        let pld = self.read_packet().await?;
        match pld[0] {
            0x00 => {
                self.handle_ok::<CommonOkPacket>(&pld)?;
                Ok(Meta::Empty)
            }
            // LOCAL INFILE: the driver answered with no handler as an empty file.
            0xfb => {
                self.write_packet(&[]).await?;
                let payload = self.read_packet().await?;
                self.handle_ok::<CommonOkPacket>(&payload)?;
                Ok(Meta::Empty)
            }
            _ => {
                let mut reader = &pld[..];
                let column_count = reader.read_lenenc_int().map_err(io_err)?;
                let mut columns: Vec<Column> = Vec::with_capacity(column_count as usize);
                for _ in 0..column_count {
                    let pld = self.read_packet().await?;
                    columns.push(ParseBuf(&pld).parse(()).map_err(io_err)?);
                }
                // The EOF after the column definitions.
                self.drop_packet().await?;
                self.st.has_results = column_count > 0;
                Ok(Meta::Rows(columns.into()))
            }
        }
    }

    async fn next_row_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.st.has_results {
            return Ok(None);
        }
        let pld = self.read_packet().await?;
        if self.has_capability(CapabilityFlags::CLIENT_DEPRECATE_EOF) {
            if pld[0] == 0xfe && pld.len() < MAX_PAYLOAD_LEN {
                self.st.has_results = false;
                self.handle_ok::<ResultSetTerminator>(&pld)?;
                return Ok(None);
            }
        } else if pld[0] == 0xfe && pld.len() < 8 {
            self.st.has_results = false;
            self.handle_ok::<OldEofPacket>(&pld)?;
            return Ok(None);
        }
        Ok(Some(pld))
    }

    /// The rows of the result set `meta` opened (all of them), then every further result set the
    /// statement produced is read and dropped, as the driver's `QueryResult` did when dropped.
    async fn rows(&mut self, meta: Meta, binary: bool) -> Result<Vec<Row>> {
        let mut out = Vec::new();
        if let Meta::Rows(columns) = meta {
            while let Some(pld) = self.next_row_packet().await? {
                let row = if binary {
                    ParseBuf(&pld)
                        .parse::<RowDeserializer<ServerSide, Binary>>(columns.clone())
                        .map_err(io_err)?
                        .into_inner()
                } else {
                    ParseBuf(&pld)
                        .parse::<RowDeserializer<(), Text>>(columns.clone())
                        .map_err(io_err)?
                        .into_inner()
                };
                out.push(row);
            }
        }
        while self.more_results_exists() {
            let meta = self.handle_result_set().await?;
            if let Meta::Rows(_) = meta {
                while self.next_row_packet().await?.is_some() {}
            }
        }
        Ok(out)
    }

    /// Roll back a transaction dropped uncommitted.
    async fn settle(&mut self) -> Result<()> {
        if std::mem::take(&mut self.rollback_pending) {
            self.query_raw("ROLLBACK").await?;
        }
        Ok(())
    }

    async fn query_raw(&mut self, query: &str) -> Result<Vec<Row>> {
        self.write_command(Command::COM_QUERY, query.as_bytes())
            .await?;
        let meta = self.handle_result_set().await?;
        self.rows(meta, false).await
    }

    // ── prepared statements ────────────────────────────────────────────────────────────────────

    async fn prepare(&mut self, query: &[u8]) -> Result<Arc<Stmt>> {
        if let Some(s) = self.st.stmts.get(query) {
            return Ok(s.clone());
        }
        self.write_command(Command::COM_STMT_PREPARE, query).await?;
        let pld = self.read_packet().await?;
        let stmt = ParseBuf(&pld).parse::<StmtPacket>(()).map_err(io_err)?;
        if stmt.num_params() > 0 {
            for _ in 0..stmt.num_params() {
                self.drop_packet().await?;
            }
            self.drop_packet().await?;
        }
        if stmt.num_columns() > 0 {
            for _ in 0..stmt.num_columns() {
                self.drop_packet().await?;
            }
            self.drop_packet().await?;
        }
        let s = Arc::new(Stmt {
            id: stmt.statement_id(),
            num_params: stmt.num_params(),
        });
        if self.st.opts.stmt_cache_size > 0 {
            if self.st.stmts.len() >= self.st.opts.stmt_cache_size {
                let old: Vec<u32> = self.st.stmts.drain().map(|(_, s)| s.id).collect();
                for id in old {
                    self.write_command_raw(&ComStmtClose::new(id)).await?;
                }
            }
            self.st.stmts.insert(query.to_vec(), s.clone());
        }
        Ok(s)
    }

    async fn send_long_data(&mut self, stmt_id: u32, params: &[Value]) -> Result<()> {
        for (i, value) in params.iter().enumerate() {
            if let Value::Bytes(bytes) = value {
                let chunks: Vec<&[u8]> = if bytes.is_empty() {
                    vec![&[][..]]
                } else {
                    bytes.chunks(MAX_PAYLOAD_LEN - 6).collect()
                };
                for chunk in chunks {
                    let cmd = ComStmtSendLongData::new(stmt_id, i as u16, Cow::Borrowed(chunk));
                    self.write_command_raw(&cmd).await?;
                }
            }
        }
        Ok(())
    }

    async fn execute(&mut self, query: &str, params: Params) -> Result<Meta> {
        self.settle().await?;
        let parsed = ParsedNamedParams::parse(query.as_bytes())
            .map_err(|_| Error::DriverError(DriverError::MixedParams))?;
        let named: Option<Vec<Vec<u8>>> = if parsed.params().is_empty() {
            None
        } else {
            Some(parsed.params().iter().map(|p| p.to_vec()).collect())
        };
        let positional = parsed.query().to_vec();
        drop(parsed);
        let stmt = self.prepare(&positional).await?;
        let params = match params {
            Params::Named(_) => match &named {
                Some(n) => params.into_positional(n).map_err(|e| {
                    Error::DriverError(DriverError::MissingNamedParameter(
                        String::from_utf8_lossy(&e.0).into_owned(),
                    ))
                })?,
                None => return Err(DriverError::NamedParamsForPositionalQuery.into()),
            },
            p => p,
        };
        let values: Vec<Value> = match params {
            Params::Empty => Vec::new(),
            Params::Positional(v) => v,
            Params::Named(_) => unreachable!("made positional above"),
        };
        if stmt.num_params as usize != values.len() {
            return Err(DriverError::MismatchedStmtParams(stmt.num_params, values.len()).into());
        }
        let (body, as_long_data) = ComStmtExecuteRequestBuilder::new(stmt.id).build(&values);
        let mut buf = Vec::new();
        body.serialize(&mut buf);
        if as_long_data {
            self.send_long_data(stmt.id, &values).await?;
        }
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await?;
        self.handle_result_set().await
    }

    // ── the driver's `Queryable` ───────────────────────────────────────────────────────────────

    /// `COM_QUERY`, every row (text protocol), as `T`.
    pub async fn query<T: FromRow>(&mut self, query: impl AsRef<str>) -> Result<Vec<T>> {
        self.settle().await?;
        let rows = self.query_raw(query.as_ref()).await?;
        Ok(rows.into_iter().map(from_row::<T>).collect())
    }

    /// `COM_QUERY`, the first row (text protocol), as `T`.
    pub async fn query_first<T: FromRow>(&mut self, query: impl AsRef<str>) -> Result<Option<T>> {
        self.settle().await?;
        let rows = self.query_raw(query.as_ref()).await?;
        Ok(rows.into_iter().next().map(from_row::<T>))
    }

    /// `COM_QUERY`, its rows dropped.
    pub async fn query_drop(&mut self, query: impl AsRef<str>) -> Result<()> {
        self.settle().await?;
        self.query_raw(query.as_ref()).await.map(drop)
    }

    /// A prepared statement, every row (binary protocol), as `T`.
    pub async fn exec<T: FromRow>(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<Vec<T>> {
        let params = params.into();
        let meta = self.execute(query.as_ref(), params).await?;
        let rows = self.rows(meta, true).await?;
        Ok(rows.into_iter().map(from_row::<T>).collect())
    }

    /// A prepared statement, the first row (binary protocol), as `T`.
    pub async fn exec_first<T: FromRow>(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<Option<T>> {
        let params = params.into();
        let meta = self.execute(query.as_ref(), params).await?;
        let rows = self.rows(meta, true).await?;
        Ok(rows.into_iter().next().map(from_row::<T>))
    }

    /// A prepared statement, its rows dropped.
    pub async fn exec_drop(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<()> {
        let params = params.into();
        let meta = self.execute(query.as_ref(), params).await?;
        self.rows(meta, true).await.map(drop)
    }

    /// A prepared statement; what it affected.
    pub async fn exec_iter(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<Affected> {
        self.exec_drop(query, params).await?;
        Ok(Affected(self.affected_rows()))
    }

    /// One prepared statement, run once per parameter set.
    pub async fn exec_batch<P: Into<Params>>(
        &mut self,
        query: impl AsRef<str>,
        params: impl IntoIterator<Item = P>,
    ) -> Result<()> {
        let all: Vec<Params> = params.into_iter().map(Into::into).collect();
        for p in all {
            self.exec_drop(query.as_ref(), p).await?;
        }
        Ok(())
    }

    /// `COM_PING`.
    pub async fn ping(&mut self) -> Result<()> {
        self.write_command(Command::COM_PING, &[]).await?;
        self.drop_packet().await
    }

    /// The rows the last statement affected.
    #[must_use]
    pub fn affected_rows(&self) -> u64 {
        self.st
            .ok
            .as_ref()
            .map(OkPacket::affected_rows)
            .unwrap_or_default()
    }

    /// `START TRANSACTION` (the driver's `TxOpts::default()`: the server's isolation level).
    ///
    /// # Errors
    /// The statement's failure.
    pub async fn start_transaction(&mut self) -> Result<Transaction<'_>> {
        self.query_drop("START TRANSACTION").await?;
        Ok(Transaction {
            conn: self,
            done: false,
        })
    }
}

/// A transaction; rolled back unless committed (before the connection's next statement).
pub struct Transaction<'a> {
    conn: &'a mut Conn,
    done: bool,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.conn.rollback_pending = true;
        }
    }
}

impl std::ops::Deref for Transaction<'_> {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        self.conn
    }
}

impl std::ops::DerefMut for Transaction<'_> {
    fn deref_mut(&mut self) -> &mut Conn {
        self.conn
    }
}

impl Transaction<'_> {
    /// `COMMIT`.
    ///
    /// # Errors
    /// The statement's failure.
    pub async fn commit(mut self) -> Result<()> {
        self.conn.query_drop("COMMIT").await?;
        self.done = true;
        Ok(())
    }

    /// `ROLLBACK`.
    ///
    /// # Errors
    /// The statement's failure.
    pub async fn rollback(mut self) -> Result<()> {
        self.conn.query_drop("ROLLBACK").await?;
        self.done = true;
        Ok(())
    }

    /// The last statement's insert id (`None` for none).
    #[must_use]
    pub fn last_insert_id(&self) -> Option<u64> {
        self.conn.st.ok.as_ref().and_then(OkPacket::last_insert_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{Opts, UrlError};

    #[test]
    fn a_url_parses_as_the_driver_parsed_it() {
        let o =
            Opts::from_url("mysql://u%40x:p%3Ass@db.internal:3307/busbar?compress=true").unwrap();
        assert_eq!(o.user.as_deref(), Some("u@x"));
        assert_eq!(o.pass.as_deref(), Some("p:ss"));
        assert_eq!(o.target(), "db.internal:3307");
        assert_eq!(o.db_name.as_deref(), Some("busbar"));
        assert!(o.compress);
        let o = Opts::from_url("mysql://u@[::1]/d").unwrap();
        assert_eq!(o.target(), "[::1]:3306");
        assert_eq!(o.address(), "::1:3306");
        assert_eq!(o.pass, None);
        let o = Opts::from_url("mysql://u@localhost/d?socket=/run/mysqld/mysqld.sock").unwrap();
        assert_eq!(o.target(), "unix:/run/mysqld/mysqld.sock");
    }

    #[test]
    fn what_the_driver_refused_is_refused_in_its_words() {
        let e = |u: &str| Opts::from_url(u).unwrap_err().to_string();
        assert_eq!(
            e("postgres://u@h/d"),
            "URL scheme `postgres' is not supported"
        );
        assert_eq!(e("mysql://u@h/d?bogus=1"), "Unknown URL parameter `bogus'");
        assert_eq!(
            e("mysql://u@h/d?require_ssl=true"),
            "Unknown URL parameter `require_ssl'"
        );
        assert_eq!(
            e("mysql://u@h/d?port=x"),
            "Invalid value `x' for URL parameter `port'"
        );
        assert_eq!(
            e("mysql://u@h/d?pool_max=5"),
            "Invalid pool constraints: pool_min (10) > pool_max (5)"
        );
        assert_eq!(
            e("mysql://u@h/d?compress=maybe"),
            "Invalid value `maybe' for URL parameter `compress'"
        );
        assert!(matches!(
            Opts::from_url("not a url"),
            Err(UrlError::ParseError(_))
        ));
        assert_eq!(
            e("not a url"),
            "URL ParseError { relative URL without a base }"
        );
    }
}
