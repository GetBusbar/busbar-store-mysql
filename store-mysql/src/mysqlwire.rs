// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL client protocol over the host's connector: the `mysql` driver's connection logic (`mysql` 28, the `minimal-rust` build), every byte through the op's one connection ([`Wire`], the store SDK's `wire`), so this store opens no socket of its own.

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
use mysql_common::packets::NullBitmap;
use mysql_common::packets::{
    AuthPlugin, AuthSwitchRequest, Column, ComStmtClose, ComStmtExecuteRequestBuilder,
    ComStmtSendLongData, CommonOkPacket, ErrPacket, HandshakePacket, OkPacketDeserializer,
    OkPacketKind, OldAuthSwitchRequest, OldEofPacket, ResultSetTerminator, StmtPacket,
};
use mysql_common::proto::codec::{Compression, PacketCodec};
use mysql_common::proto::MySerialize;
use mysql_common::row::convert::{from_row_opt, FromRow};
use mysql_common::value::{BinValue, ServerSide, TextValue, ValueDeserializer};
use zeroize::{Zeroize, Zeroizing};

pub use mysql_common::params::Params;
pub use mysql_common::row::Row;
pub use mysql_common::value::Value;

use crate::credentials::{CredUrl, MysqlAuth, MysqlHandshake, PasswordAt};
use busbar_contract::abi::sdk::cred::Seal;
use busbar_contract::abi::sdk::store::wire::Wire;

struct SecretParams(Params);

impl Drop for SecretParams {
    fn drop(&mut self) {
        match &mut self.0 {
            Params::Empty => {}
            Params::Positional(values) => values.iter_mut().for_each(wipe_value),
            Params::Named(values) => values.values_mut().for_each(wipe_value),
        }
    }
}

struct SecretValues(Vec<Value>);

impl Drop for SecretValues {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(wipe_value);
    }
}

fn wipe_value(value: &mut Value) {
    if let Value::Bytes(bytes) = value {
        bytes.zeroize();
    }
}

struct SecretRows(Vec<Row>);
impl Drop for SecretRows {
    fn drop(&mut self) {
        for row in &mut self.0 {
            for index in 0..row.len() {
                if let Some(mut value) = row.take::<Value, _>(index) {
                    wipe_value(&mut value);
                }
            }
        }
    }
}

struct SecretBytes(BytesMut);

fn reserve_wiping(buf: &mut BytesMut, additional: usize) {
    if additional > buf.capacity() - buf.len() {
        let capacity = buf
            .len()
            .checked_add(additional)
            .expect("buffer capacity overflow");
        let mut replacement = BytesMut::with_capacity(capacity);
        replacement.extend_from_slice(buf);
        buf.as_mut().zeroize();
        *buf = replacement;
    }
}
impl std::ops::Deref for SecretBytes {
    type Target = BytesMut;
    fn deref(&self) -> &BytesMut {
        &self.0
    }
}
impl std::ops::DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut BytesMut {
        &mut self.0
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
    }
}

/// Admission posture, also restored after every successful connection reset.
pub(crate) const NATIVE_INIT: &[&str] = &[
    "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
    "SET SESSION time_zone = '+00:00'",
    "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
];
const BATCH_NATIVE_INIT: &str = "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), time_zone = '+00:00', transaction_isolation = 'REPEATABLE-READ'";

/// Older dialects and managed SQL filters can reject the combined spelling.
/// Retry only the existing authoritative commands, never a transport/codec fault.
pub(crate) fn batching_refused(error: &Error) -> bool {
    matches!(error, Error::MySqlError(error) if matches!(error.code,
        1064 | 1142 | 1143 | 1193 | 1227))
}

const MAX_COLUMNS: usize = 4096;
const MAX_RESULT_ROWS: usize = 1_000_000;
const MAX_RESULT_BYTES: usize = 256 * 1024 * 1024;
const MAX_RESULT_SETS: usize = 64;
const MAX_PROGRESS_PACKETS: usize = 1024;
const MAX_DEFAULT_PACKET: usize = 64 * 1024 * 1024;

fn result_budget_exceeded(rows: usize, bytes: usize) -> bool {
    rows > MAX_RESULT_ROWS || bytes > MAX_RESULT_BYTES
}

/// A server-side failure (an ERR packet).
#[derive(Eq, PartialEq, Clone)]
pub struct MySqlError {
    pub state: String,
    pub message: String,
    pub code: u16,
}

impl MySqlError {
    /// The server's text with any stored or offered VALUE left out: a duplicate entry names the key it hit (`duplicate credentials.uq_cred_public`), an incorrect-value error the column.
    pub(crate) fn rendered(&self) -> String {
        match self.code {
            // ER_DUP_ENTRY: `Duplicate entry '<value>' for key '<key>'`. The value is arbitrary
            // text, so the key is read from the END of the message.
            crate::ER_DUP_ENTRY => match self
                .message
                .strip_suffix('\'')
                .and_then(|m| m.rfind('\'').map(|at| &m[at + 1..]))
            {
                Some(key) => format!("duplicate {key}"),
                None => "duplicate key".to_owned(),
            },

            1292 | 1366 => match self.message.rfind(" for column ") {
                Some(at) => {
                    let column = &self.message[at + " for column ".len()..];
                    let column = column.split(" at row ").next().unwrap_or(column);
                    format!("invalid value for column {column}")
                }
                None => "invalid value".to_owned(),
            },
            _ => self.message.clone(),
        }
    }
}

impl fmt::Display for MySqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ERROR {} ({}): {}",
            self.code,
            self.state,
            self.rendered()
        )
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
    AuthRefused(String),
    MissingNamedParameter(String),
    NamedParamsForPositionalQuery,
    MixedParams,
    UnknownAuthPlugin(String),
    OldMysqlPasswordDisabled,
    CleartextPluginDisabled,
    /// A row did not convert to the type asked for (its name, never the value).
    RowConversion(&'static str),
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
            DriverError::AuthRefused(message) => f.write_str(message),
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
            DriverError::RowConversion(ty) => {
                write!(f, "A row value does not convert to type `{ty}'")
            }
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
    /// A refusal in this store's own words (a parameter it does not support; text withheld because the URL carries a password).
    Refused(String),
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
            UrlError::Refused(m) => f.write_str(m),
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
    /// This error with the URL's password redacted from every text it carries.
    pub(crate) fn scrubbed(self, opts: &Opts) -> Self {
        match self {
            Error::IoError(m) => Error::IoError(opts.scrub(m)),
            Error::MySqlError(mut e) => {
                e.message = opts.scrub(e.message);
                Error::MySqlError(e)
            }
            Error::DriverError(DriverError::CouldNotConnect(Some((a, d)))) => {
                Error::DriverError(DriverError::CouldNotConnect(Some((a, opts.scrub(d)))))
            }
            Error::DriverError(DriverError::UnknownAuthPlugin(name)) => {
                Error::DriverError(DriverError::UnknownAuthPlugin(opts.scrub(name)))
            }
            e => e,
        }
    }

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

/// The driver's per-connection prepared-statement cache.
const STMT_CACHE_DEFAULT: usize = 32;

/// The supported `mysql://` URL settings; host-owned socket options are explicitly refused.
#[derive(Clone, PartialEq, Eq)]
pub struct Opts {
    pub user: Option<String>,
    pub host: url::Host,
    pub port: u16,
    pub db_name: Option<String>,
    /// A unix-socket path (`socket=`): the connection goes there instead of `host:port`.
    pub socket: Option<String>,
    pub compress: bool,
    pub compression_level: u32,
    pub tcp_connect_timeout_ms: Option<u64>,
    pub max_allowed_packet: Option<usize>,
    pub secure_auth: bool,
    pub enable_cleartext_plugin: bool,
    pub stmt_cache_size: usize,
    /// Captured before any public URL parsing; clones share SDK-owned secret storage.
    credential_url: CredUrl,
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

/// MySQL's smallest `max_allowed_packet` (1024 bytes).
const MAX_PACKET_FLOOR: usize = 1024;

/// MySQL's largest `max_allowed_packet` (1 GiB).
const MAX_PACKET_CEILING: usize = 1 << 30;

/// The refusal of a URL parameter this store accepts nowhere because it could never apply.
fn not_supported(key: &str, why: &str) -> UrlError {
    UrlError::Refused(format!(
        "mysql store: URL parameter `{key}` is not supported: {why}"
    ))
}

/// The packet ceiling a server-reported `@@max_allowed_packet` may set (0 when it could not be read) and must lie in
/// MySQL's own range, the same bounds the URL parameter is held to.
fn checked_packet_ceiling(n: usize) -> Result<usize> {
    if !(MAX_PACKET_FLOOR..=MAX_PACKET_CEILING).contains(&n) {
        return Err(DriverError::SetupError.into());
    }
    Ok(n)
}

fn is_tls_parameter(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.starts_with("ssl")
        || k.starts_with("tls")
        || matches!(k.as_str(), "require_ssl" | "verify_ca" | "verify_identity")
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode(s.as_bytes())
        .decode_utf8_lossy()
        .into_owned()
}

impl Opts {
    /// Capture the password from a `mysql://user:pass@host:port/db?key=value&...` URL, then parse its public connection options with the driver's validation and refusals.
    #[cfg(test)]
    pub fn from_url(url_str: &str) -> Result<Opts, UrlError> {
        let captured = CredUrl::parse(url_str.trim_matches(|ch: char| ch <= ' '))
            .map_err(|_| UrlError::BadUrl)?;
        Self::from_captured(captured)
    }

    /// Redact server and connector echoes within the SDK, without exposing the password.
    #[must_use]
    pub fn scrub(&self, text: String) -> String {
        self.credential_url
            .redact_echo(&zeroize::Zeroizing::new(text))
    }

    pub(crate) fn from_captured(credential_url: CredUrl) -> Result<Opts, UrlError> {
        let has_password = credential_url.password().is_some();
        Self::parse_captured(credential_url).map_err(|error| match error {
            UrlError::UnknownParameter(_) | UrlError::InvalidValue(..) if has_password => UrlError::Refused(
                "mysql store: invalid URL parameter (its text is withheld: the URL carries a password; percent-encode `?`, `@`, `/` and `:` inside it)".into(),
            ),
            error => error,
        })
    }

    fn parse_captured(credential_url: CredUrl) -> Result<Opts, UrlError> {
        let url_str = credential_url.public();
        if credential_url.password_at() == Some(PasswordAt::UserinfoUnencoded) {
            return Err(UrlError::Refused(
                "mysql store: invalid URL parameter (its text is withheld: the URL carries a password; percent-encode `?`, `@`, `/` and `:` inside it)".into(),
            ));
        }
        if credential_url.password_at() == Some(PasswordAt::Query("pass")) {
            return Err(UrlError::UnknownParameter("pass".into()));
        }
        let url = url::Url::parse(url_str)?;
        if url.scheme() != "mysql" {
            return Err(UrlError::UnsupportedScheme(url.scheme().to_string()));
        }
        if url.cannot_be_a_base() {
            return Err(UrlError::BadUrl);
        }
        let user = Some(url.username()).filter(|u| !u.is_empty()).map(decode);
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
            host,
            port,
            db_name,
            socket: None,
            compress: false,
            compression_level: Compression::default().level(),
            tcp_connect_timeout_ms: None,
            max_allowed_packet: None,
            secure_auth: true,
            enable_cleartext_plugin: false,
            stmt_cache_size: STMT_CACHE_DEFAULT,
            credential_url: credential_url.clone(),
        };
        let pairs: HashMap<String, String> = url.query_pairs().into_owned().collect();
        for (key, value) in &pairs {
            let invalid = || UrlError::InvalidValue(key.to_string(), value.to_string());
            match key.as_str() {
                "pool_min" | "pool_max" => {
                    return Err(not_supported(
                        key,
                        &format!(
                            "this store keeps {} connections over the host's connector",
                            crate::KEPT_CONNECTIONS
                        ),
                    ));
                }
                "user" => opts.user = Some(value.to_string()),
                "host" => {
                    // A bare IPv6 literal (no brackets) is an address, not a domain name.
                    opts.host = url::Host::parse(value)
                        .or_else(|_| value.parse::<std::net::Ipv6Addr>().map(url::Host::Ipv6))
                        .unwrap_or_else(|_| url::Host::Domain(value.to_owned()));
                }
                "port" => opts.port = value.parse().map_err(|_| invalid())?,
                "socket" => opts.socket = Some(value.to_string()),
                "db_name" => opts.db_name = Some(value.to_string()),

                "prefer_socket"
                | "reset_connection"
                | "check_health"
                | "tcp_keepalive_time_ms"
                | "tcp_keepalive_probe_interval_secs"
                | "tcp_keepalive_probe_count"
                | "tcp_user_timeout_ms" => {
                    return Err(not_supported(
                        key,
                        "the host's connector owns the connection and its sockets, so this \
                         option could never apply",
                    ));
                }
                "enable_cleartext_plugin" => {
                    opts.enable_cleartext_plugin = value.parse().map_err(|_| invalid())?;
                }
                "secure_auth" => opts.secure_auth = value.parse().map_err(|_| invalid())?,
                "server_public_key_sha256" => {
                    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(invalid());
                    }
                }
                "compress" => {
                    opts.compress = true;
                    opts.compression_level = match value.parse::<u32>() {
                        Ok(level @ 0..=9) => level,
                        Ok(_) => return Err(invalid()),
                        Err(_) => match value.as_str() {
                            "fast" => Compression::fast().level(),
                            "best" => Compression::best().level(),
                            "true" => Compression::default().level(),
                            _ => return Err(invalid()),
                        },
                    };
                }
                "tcp_connect_timeout_ms" => {
                    opts.tcp_connect_timeout_ms = Some(value.parse().map_err(|_| invalid())?);
                }
                "stmt_cache_size" => {
                    return Err(not_supported(
                        key,
                        "this store's per-connection statement cache has a fixed size",
                    ));
                }
                "max_allowed_packet" => {
                    let n: usize = value.parse().map_err(|_| invalid())?;
                    if !(MAX_PACKET_FLOOR..=MAX_PACKET_CEILING).contains(&n) {
                        return Err(UrlError::Refused(format!(
                            "mysql store: URL parameter `max_allowed_packet` must be between \
                             {MAX_PACKET_FLOOR} and {MAX_PACKET_CEILING} bytes (MySQL's range)"
                        )));
                    }
                    opts.max_allowed_packet = Some(n);
                }
                k if is_tls_parameter(k) => {
                    let k = if credential_url.password().is_some() {
                        "withheld: the URL carries a password"
                    } else {
                        k
                    };
                    return Err(UrlError::Refused(format!(
                        "mysql store: URL parameter `{k}` is not supported: TLS is not supported by \
                         this store (the connection is plaintext over the host's connector)"
                    )));
                }
                _ => return Err(UrlError::UnknownParameter(key.to_string())),
            }
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

/// Where a connection's bytes go: the op's wire (the host's connector), or, in this crate's own tests only, a plain TCP stream to the live server (the internals' tests drive the client directly; nothing here is in the shipped image).
pub(crate) enum Io {
    Wire(Wire),
    #[cfg(test)]
    Tcp(std::net::TcpStream),
}

impl Io {
    async fn write_sealed(&mut self, seal: Seal) -> Result<(), String> {
        match self {
            Io::Wire(w) => w.write_sealed(seal).await.map_err(|e| e.to_string()),
            #[cfg(test)]
            Io::Tcp(s) => tests::write_sealed_tcp(s, seal),
        }
    }

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
                    reserve_wiping(into, i.len());
                    into.extend_from_slice(i);
                    i.zeroize();
                });
                Ok(n)
            }
            #[cfg(test)]
            Io::Tcp(s) => {
                let mut buf = Zeroizing::new([0_u8; 16 * 1024]);
                let n = std::io::Read::read(s, &mut *buf).map_err(|e| e.to_string())?;
                reserve_wiping(into, n);
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

/// A prepared statement, as the connection's cache keeps it.
struct Stmt {
    id: u32,
    num_params: u16,
}

/// A query text parsed once: the positional text sent to the server and, for a named query, the order its parameters were named in.
struct ParsedQuery {
    positional: Vec<u8>,
    named: Option<Vec<Vec<u8>>>,
}

/// What a connection carries across the ops that reuse it (the store SDK's kept set keeps it with the connection, [`Wire::set_session`]).
struct State {
    opts: Arc<Opts>,
    codec: PacketCodec,
    inbuf: SecretBytes,
    caps: CapabilityFlags,
    status: StatusFlags,
    server_version: Option<(u16, u16, u16)>,
    mariadb_version: Option<(u16, u16, u16)>,
    connection_id: u32,
    nonce: Vec<u8>,
    auth_plugin: AuthPlugin<'static>,
    /// Prepared statements by their (positional) query text.
    stmts: HashMap<Vec<u8>, Arc<Stmt>>,
    /// Each query text's parse into (positional text, named-parameter order), so a repeated query is not re-parsed per execute.
    parsed: HashMap<String, Arc<ParsedQuery>>,
    /// The last OK packet (affected rows, last insert id).
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

/// ONE CONNECTION TO THE SERVER over the op's transport.
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

/// The connect attributes the driver sends (`performance_schema.session_connect_attrs`).
fn connect_attrs() -> HashMap<String, String> {
    let program_name = std::env::args_os()
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut attrs = HashMap::new();
    attrs.insert("_client_name".into(), "rust-mysql-simple".into());
    attrs.insert("_client_version".into(), env!("CARGO_PKG_VERSION").into());
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
            inbuf: SecretBytes(BytesMut::new()),
            caps: CapabilityFlags::empty(),
            status: StatusFlags::empty(),
            server_version: None,
            mariadb_version: None,
            connection_id: 0,
            nonce: Vec::new(),
            auth_plugin: AuthPlugin::MysqlNativePassword,
            stmts: HashMap::new(),
            parsed: HashMap::new(),
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

    /// THE OP'S CONNECTION over `wire` (need `need`, the target the URL names): the kept one when it is idle and answers a ping (the driver pool's `check_health`), else a fresh dial, its handshake, authentication, `max_allowed_packet` and the `init` statements, exactly as the driver's `Conn::new` ran them.
    pub async fn open(wire: Wire, opts: &Arc<Opts>, need: u32, init: &[&str]) -> Result<Conn> {
        Self::open_unscrubbed(wire, opts, need, init)
            .await
            .map_err(|e| e.scrubbed(opts))
    }

    async fn open_unscrubbed(
        wire: Wire,
        opts: &Arc<Opts>,
        need: u32,
        init: &[&str],
    ) -> Result<Conn> {
        let timeout = opts
            .tcp_connect_timeout_ms
            .map_or(0, |ms| u32::try_from(ms).unwrap_or(u32::MAX));
        let could_not = |e: busbar_contract::abi::sdk::conn::ConnFailure| {
            Error::DriverError(DriverError::CouldNotConnect(Some((
                opts.address(),
                opts.scrub(e.to_string()),
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

    /// The op is done with the connection: reset it for the next op (the driver pool's `reset_connection`: `COM_RESET_CONNECTION`, then the `init` statements again) and keep it; a connection whose stream failed, or that does not reset, is discarded.
    pub async fn release(mut self, init: &[&str]) {
        if self.broken || !self.st.inbuf.is_empty() || self.st.has_results {
            return;
        }
        let reset = match (self.st.server_version, self.st.mariadb_version) {
            (Some(v), _) if v >= (5, 7, 3) => true,
            (_, Some(v)) if v >= (10, 2, 7) => true,
            _ => false,
        };

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
        self.initialize(init).await
    }

    async fn initialize(&mut self, init: &[&str]) -> Result<()> {
        if init == NATIVE_INIT {
            match self.query_drop(BATCH_NATIVE_INIT).await {
                Ok(()) => return Ok(()),
                Err(error) if batching_refused(&error) => {}
                Err(error) => return Err(error),
            }
        }
        for command in init {
            self.query_drop(command).await?;
        }
        Ok(())
    }

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

    async fn read_packet(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        for _ in 0..MAX_PROGRESS_PACKETS {
            let mut buffer = Zeroizing::new(Vec::new());
            match self.raw_read(&mut buffer).await {
                Ok(()) if buffer.first() == Some(&0xff) => {
                    match ParseBuf(&buffer)
                        .parse::<ErrPacket<'_>>(self.st.caps)
                        .map_err(|e| self.parse_err(e))?
                    {
                        ErrPacket::Error(server_error) => {
                            self.handle_err();
                            let mut e = MySqlError::from(server_error);
                            e.message = self.st.opts.scrub(e.message);
                            return Err(Error::MySqlError(e));
                        }
                        ErrPacket::Progress(_) => continue,
                    }
                }

                Ok(()) if buffer.is_empty() => {
                    self.broken = true;
                    return Err(DriverError::UnexpectedPacket.into());
                }
                Ok(()) => return Ok(buffer),
                Err(e) => {
                    self.handle_err();
                    return Err(e);
                }
            }
        }
        self.broken = true;
        Err(DriverError::UnexpectedPacket.into())
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut out = SecretBytes(BytesMut::new());
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

    async fn write_command_raw<T: MySerialize>(&mut self, cmd: &T) -> Result<()> {
        let mut buf = Zeroizing::new(Vec::new());
        cmd.serialize(&mut buf);
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await
    }

    async fn write_command(&mut self, cmd: Command, data: &[u8]) -> Result<()> {
        let mut buf = Zeroizing::new(Vec::with_capacity(1 + data.len()));
        buf.push(cmd as u8);
        buf.extend_from_slice(data);
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await
    }

    /// A packet that fails to parse leaves the rest of its reply unread: the stream is desynced,
    /// so the connection is marked broken and `release` discards it.
    fn parse_err(&mut self, e: std::io::Error) -> Error {
        self.broken = true;
        io_err(e)
    }

    fn handle_ok<T: OkPacketKind>(&mut self, buffer: &[u8]) -> Result<()> {
        let ok = ParseBuf(buffer)
            .parse::<OkPacketDeserializer<T>>(self.st.caps)
            .map_err(|e| self.parse_err(e))?
            .into_inner();
        self.st.status = ok.status_flags();
        Ok(())
    }

    fn handle_err(&mut self) {
        self.st.status = StatusFlags::empty();
        self.st.has_results = false;
    }

    fn more_results_exists(&self) -> bool {
        self.st
            .status
            .contains(StatusFlags::SERVER_MORE_RESULTS_EXISTS)
    }

    fn has_capability(&self, flag: CapabilityFlags) -> bool {
        self.st.caps.contains(flag)
    }

    fn client_flags(&self) -> CapabilityFlags {
        let mut flags = CapabilityFlags::CLIENT_PROTOCOL_41
            | CapabilityFlags::CLIENT_SECURE_CONNECTION
            | CapabilityFlags::CLIENT_LONG_PASSWORD
            | CapabilityFlags::CLIENT_TRANSACTIONS
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
            .map_err(|e| self.parse_err(e))?;
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
            self.st
                .codec
                .compress(Compression::new(self.st.opts.compression_level));
        }
        let max_allowed_packet = match self.st.opts.max_allowed_packet {
            Some(x) => x,
            None => {
                let v: Option<Row> = self.query_first("SELECT @@max_allowed_packet").await?;
                v.and_then(|mut r| r.take_opt::<usize, _>(0))
                    .and_then(std::result::Result::ok)
                    .ok_or_else(|| {
                        Error::IoError("server max_allowed_packet is missing or invalid".into())
                    })?
                    .min(MAX_DEFAULT_PACKET)
            }
        };
        let max_allowed_packet = checked_packet_ceiling(max_allowed_packet)?;
        self.st.codec.max_allowed_packet = max_allowed_packet;
        self.initialize(init).await
    }

    async fn write_handshake_response(&mut self) -> Result<()> {
        let seq = self.next_auth_seq()?;
        let attrs = connect_attrs();
        let attrs: Vec<(&[u8], &[u8])> = attrs
            .iter()
            .map(|(key, value)| (key.as_bytes(), value.as_bytes()))
            .collect();
        let seal = self
            .st
            .opts
            .credential_url
            .mysql_handshake_response(&MysqlHandshake {
                seq,
                capabilities: self.st.caps.bits(),
                max_packet: self
                    .st
                    .opts
                    .max_allowed_packet
                    .unwrap_or(DEFAULT_MAX_ALLOWED_PACKET) as u32,
                collation: if self.st.server_version.unwrap_or((0, 0, 0)) >= (5, 5, 3) {
                    45
                } else {
                    33
                },
                user: self.st.opts.user.as_deref().unwrap_or_default().as_bytes(),
                database: self.st.opts.db_name.as_deref().map(str::as_bytes),
                auth: self.mysql_auth()?,
                nonce: &self.st.nonce,
                attrs: &attrs,
            })
            .map_err(auth_refused)?;
        self.write_auth(seal).await
    }

    /// Auth is uncompressed and each SDK recipe emits exactly one complete packet.
    fn next_auth_seq(&mut self) -> Result<u8> {
        let mut header = BytesMut::new();
        self.st
            .codec
            .encode(&mut &[][..], &mut header)
            .map_err(Error::CodecError)?;
        Ok(header[3])
    }

    fn mysql_auth(&self) -> Result<MysqlAuth> {
        match &self.st.auth_plugin {
            AuthPlugin::MysqlNativePassword => Ok(MysqlAuth::Native),
            AuthPlugin::CachingSha2Password => Ok(MysqlAuth::CachingSha2),
            AuthPlugin::MysqlOldPassword => Ok(MysqlAuth::Old),
            AuthPlugin::MysqlClearPassword => Ok(MysqlAuth::Clear),
            other => Err(DriverError::UnknownAuthPlugin(
                String::from_utf8_lossy(other.as_bytes()).into_owned(),
            )
            .into()),
        }
    }

    async fn write_auth(&mut self, seal: Seal) -> Result<()> {
        if seal.len().saturating_sub(4) > self.st.codec.max_allowed_packet {
            self.broken = true;
            return Err(Error::CodecError(
                mysql_common::proto::codec::error::PacketCodecError::PacketTooLarge,
            ));
        }
        if let Err(e) = self.io.write_sealed(seal).await {
            self.broken = true;
            return Err(Error::IoError(self.st.opts.scrub(e)));
        }
        Ok(())
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
                            .map_err(|e| self.parse_err(e))?
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
                        .map_err(|e| self.parse_err(e))?
                        .into_owned()
                } else {
                    let _ = ParseBuf(&payload)
                        .parse::<OldAuthSwitchRequest>(())
                        .map_err(|e| self.parse_err(e))?;
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
            0x00 => Ok(()),
            0x01 => match payload.get(1) {
                Some(0x03) => {
                    let payload = self.read_packet().await?;
                    self.handle_ok::<CommonOkPacket>(&payload)
                }

                Some(0x04) => {
                    let credential = self.st.opts.credential_url.clone();
                    if self.st.socket {
                        let seq = self.next_auth_seq()?;
                        let seal = credential.mysql_clear_packet(seq).map_err(auth_refused)?;
                        self.write_auth(seal).await?;
                    } else {
                        if self.st.nonce.is_empty() {
                            return Err(DriverError::UnexpectedPacket.into());
                        }
                        self.write_packet(&[0x02]).await?;
                        let payload = self.read_packet().await?;
                        let key = payload.get(1..).unwrap_or_default();
                        let seq = self.next_auth_seq()?;
                        let seal = credential
                            .mysql_rsa_packet(seq, &self.st.nonce, key)
                            .map_err(auth_refused)?;
                        self.write_auth(seal).await?;
                    }
                    let payload = self.read_packet().await?;
                    self.handle_ok::<CommonOkPacket>(&payload)
                }
                _ => Err(DriverError::UnexpectedPacket.into()),
            },
            0xfe if !auth_switched => {
                let req = ParseBuf(&payload)
                    .parse::<AuthSwitchRequest<'_>>(())
                    .map_err(|e| self.parse_err(e))?
                    .into_owned();
                self.auth_switch(req).await
            }
            _ => Err(DriverError::UnexpectedPacket.into()),
        }
    }

    async fn auth_switch(&mut self, req: AuthSwitchRequest<'static>) -> Result<()> {
        if matches!(req.auth_plugin(), AuthPlugin::Ed25519) {
            return Err(DriverError::UnknownAuthPlugin("client_ed25519".into()).into());
        }
        if matches!(req.auth_plugin(), AuthPlugin::MysqlOldPassword) && self.st.opts.secure_auth {
            return Err(DriverError::OldMysqlPasswordDisabled.into());
        }
        if matches!(req.auth_plugin(), AuthPlugin::MysqlClearPassword)
            && !self.st.opts.enable_cleartext_plugin
        {
            return Err(DriverError::CleartextPluginDisabled.into());
        }
        self.st.nonce = req.plugin_data().to_vec();
        self.st.auth_plugin = req.auth_plugin().into_owned();
        if matches!(self.st.auth_plugin, AuthPlugin::MysqlOldPassword) && self.st.nonce.len() < 8 {
            return Err(DriverError::UnexpectedPacket.into());
        }
        if matches!(self.st.auth_plugin, AuthPlugin::Other(_)) {
            self.write_packet(&[]).await?;
        } else {
            let seq = self.next_auth_seq()?;
            let seal = self
                .st
                .opts
                .credential_url
                .mysql_auth_switch_response(seq, self.mysql_auth()?, &self.st.nonce)
                .map_err(auth_refused)?;
            self.write_auth(seal).await?;
        }
        self.continue_auth(true).await
    }

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

            0xfb => {
                self.write_packet(&[]).await?;
                let payload = self.read_packet().await?;
                self.handle_ok::<CommonOkPacket>(&payload)?;
                Ok(Meta::Empty)
            }
            _ => {
                let mut reader = &pld[..];
                let column_count = reader.read_lenenc_int().map_err(|e| self.parse_err(e))?;
                // The server's count is untrusted; 4096 is MySQL's column ceiling. A count
                // above it is refused before a definition is read, so a lying server cannot
                // stream definitions into an unbounded Vec.
                if column_count > MAX_COLUMNS as u64 {
                    self.broken = true;
                    return Err(DriverError::UnexpectedPacket.into());
                }
                let mut columns: Vec<Column> = Vec::with_capacity(
                    usize::try_from(column_count)
                        .unwrap_or(usize::MAX)
                        .min(MAX_COLUMNS),
                );
                let mut metadata_bytes = 0usize;
                for _ in 0..column_count {
                    let pld = self.read_packet().await?;
                    metadata_bytes = metadata_bytes.saturating_add(pld.len());
                    if metadata_bytes > MAX_RESULT_BYTES {
                        self.broken = true;
                        return Err(DriverError::UnexpectedPacket.into());
                    }
                    columns.push(ParseBuf(&pld).parse(()).map_err(|e| self.parse_err(e))?);
                }

                let eof = self.read_packet().await?;
                self.handle_ok::<OldEofPacket>(&eof)?;
                self.st.has_results = column_count > 0;
                Ok(Meta::Rows(columns.into()))
            }
        }
    }

    async fn next_row_packet(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
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

    /// The rows of the result set `meta` opened (all of them), then every further result set the statement produced is read and dropped, as the driver's `QueryResult` did when dropped.
    async fn rows(&mut self, meta: Meta, binary: bool) -> Result<Vec<Row>> {
        self.rows_kept(meta, binary, usize::MAX).await
    }

    async fn rows_kept(&mut self, meta: Meta, binary: bool, keep: usize) -> Result<Vec<Row>> {
        let mut out = SecretRows(Vec::new());
        let mut bytes = 0usize;
        let mut count = 0usize;
        if let Meta::Rows(columns) = meta {
            while let Some(pld) = self.next_row_packet().await? {
                bytes = bytes.saturating_add(pld.len()).saturating_add(
                    columns
                        .len()
                        .saturating_mul(std::mem::size_of::<Option<Value>>()),
                );
                count += 1;
                if result_budget_exceeded(count, bytes) {
                    self.broken = true;
                    return Err(DriverError::UnexpectedPacket.into());
                }
                if out.0.len() == keep {
                    continue;
                }
                let row =
                    parse_row(&pld, columns.clone(), binary).map_err(|e| self.parse_err(e))?;
                out.0.push(row);
            }
        }
        let mut sets = 1usize;
        while self.more_results_exists() {
            sets += 1;
            if sets > MAX_RESULT_SETS {
                self.broken = true;
                return Err(DriverError::UnexpectedPacket.into());
            }
            let meta = self.handle_result_set().await?;
            if let Meta::Rows(_) = meta {
                while let Some(packet) = self.next_row_packet().await? {
                    bytes = bytes.saturating_add(packet.len());
                    count += 1;
                    if result_budget_exceeded(count, bytes) {
                        self.broken = true;
                        return Err(DriverError::UnexpectedPacket.into());
                    }
                }
            }
        }
        Ok(std::mem::take(&mut out.0))
    }

    /// Roll back a transaction dropped uncommitted.
    async fn settle(&mut self) -> Result<()> {
        if self.rollback_pending {
            if let Err(error) = self.query_raw("ROLLBACK").await {
                self.broken = true;
                return Err(error);
            }
            self.rollback_pending = false;
        }
        Ok(())
    }

    async fn query_raw(&mut self, query: &str) -> Result<Vec<Row>> {
        self.write_command(Command::COM_QUERY, query.as_bytes())
            .await?;
        let meta = self.handle_result_set().await?;
        self.rows(meta, false).await
    }

    async fn prepare(&mut self, query: &[u8]) -> Result<Arc<Stmt>> {
        if let Some(s) = self.st.stmts.get(query) {
            return Ok(s.clone());
        }
        self.write_command(Command::COM_STMT_PREPARE, query).await?;
        let pld = self.read_packet().await?;
        let stmt = ParseBuf(&pld)
            .parse::<StmtPacket>(())
            .map_err(|e| self.parse_err(e))?;
        if usize::from(stmt.num_columns()) > MAX_COLUMNS {
            self.broken = true;
            return Err(DriverError::UnexpectedPacket.into());
        }
        let mut metadata_bytes = 0usize;
        for count in [stmt.num_params(), stmt.num_columns()] {
            if count == 0 {
                continue;
            }
            for _ in 0..count {
                let definition = self.read_packet().await?;
                metadata_bytes = metadata_bytes.saturating_add(definition.len());
                if metadata_bytes > MAX_RESULT_BYTES {
                    self.broken = true;
                    return Err(DriverError::UnexpectedPacket.into());
                }
            }
            let eof = self.read_packet().await?;
            self.handle_ok::<OldEofPacket>(&eof)?;
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
        let params = SecretParams(params);
        self.settle().await?;
        let parsed = match self.st.parsed.get(query) {
            Some(p) => p.clone(),
            None => {
                let p = ParsedNamedParams::parse(query.as_bytes())
                    .map_err(|_| Error::DriverError(DriverError::MixedParams))?;
                let named = if p.params().is_empty() {
                    None
                } else {
                    Some(p.params().iter().map(|p| p.to_vec()).collect())
                };
                let parsed = Arc::new(ParsedQuery {
                    positional: p.query().to_vec(),
                    named,
                });
                let cap = self.st.opts.stmt_cache_size;
                if cap > 0 {
                    if self.st.parsed.len() >= cap {
                        self.st.parsed.clear();
                    }
                    self.st.parsed.insert(query.to_owned(), parsed.clone());
                }
                parsed
            }
        };
        let (positional, named) = (&parsed.positional, &parsed.named);
        let stmt = self.prepare(positional).await?;
        let mut values = SecretValues(Vec::new());
        match &params.0 {
            Params::Empty => {}
            Params::Positional(v) => values.0.extend(v.iter().cloned()),
            Params::Named(map) => {
                let names = named
                    .as_ref()
                    .ok_or(DriverError::NamedParamsForPositionalQuery)?;
                for name in names {
                    let value = map.get(name).ok_or_else(|| {
                        Error::DriverError(DriverError::MissingNamedParameter(
                            String::from_utf8_lossy(name).into_owned(),
                        ))
                    })?;
                    values.0.push(value.clone());
                }
            }
        }
        let values = &values.0;
        if stmt.num_params as usize != values.len() {
            return Err(DriverError::MismatchedStmtParams(stmt.num_params, values.len()).into());
        }
        let (body, as_long_data) = ComStmtExecuteRequestBuilder::new(stmt.id).build(values);
        let mut buf = Zeroizing::new(Vec::new());
        body.serialize(&mut buf);
        if as_long_data {
            self.send_long_data(stmt.id, values).await?;
        }
        self.st.codec.reset_seq_id();
        self.write_packet(&buf).await?;
        self.handle_result_set().await
    }

    /// `COM_QUERY`, every row (text protocol), as `T`.
    pub async fn query<T: FromRow>(&mut self, query: impl AsRef<str>) -> Result<Vec<T>> {
        self.settle().await?;
        let rows = self.query_raw(query.as_ref()).await?;
        let mut rows = SecretRows(rows);
        let mut converted = Vec::with_capacity(rows.0.len());
        while let Some(row) = rows.0.pop() {
            converted.push(convert::<T>(row)?);
        }
        converted.reverse();
        Ok(converted)
    }

    /// `COM_QUERY`, the first row (text protocol), as `T`.
    pub async fn query_first<T: FromRow>(&mut self, query: impl AsRef<str>) -> Result<Option<T>> {
        self.settle().await?;
        self.write_command(Command::COM_QUERY, query.as_ref().as_bytes())
            .await?;
        let meta = self.handle_result_set().await?;
        let rows = self.rows_kept(meta, false, 1).await?;
        rows.into_iter().next().map(convert::<T>).transpose()
    }

    /// `COM_QUERY`, its rows dropped.
    pub async fn query_drop(&mut self, query: impl AsRef<str>) -> Result<()> {
        self.settle().await?;
        self.write_command(Command::COM_QUERY, query.as_ref().as_bytes())
            .await?;
        let meta = self.handle_result_set().await?;
        self.rows_kept(meta, false, 0).await.map(drop)
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
        let mut rows = SecretRows(rows);
        let mut converted = Vec::with_capacity(rows.0.len());
        while let Some(row) = rows.0.pop() {
            converted.push(convert::<T>(row)?);
        }
        converted.reverse();
        Ok(converted)
    }

    /// A prepared statement, the first row (binary protocol), as `T`.
    pub async fn exec_first<T: FromRow>(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<Option<T>> {
        let params = params.into();
        let meta = self.execute(query.as_ref(), params).await?;
        let rows = self.rows_kept(meta, true, 1).await?;
        rows.into_iter().next().map(convert::<T>).transpose()
    }

    /// A prepared statement, its rows dropped.
    pub async fn exec_drop(
        &mut self,
        query: impl AsRef<str>,
        params: impl Into<Params>,
    ) -> Result<()> {
        let params = params.into();
        let meta = self.execute(query.as_ref(), params).await?;
        self.rows_kept(meta, true, 0).await.map(drop)
    }

    /// `COM_PING`.
    pub async fn ping(&mut self) -> Result<()> {
        self.write_command(Command::COM_PING, &[]).await?;
        let packet = self.read_packet().await?;
        if packet.first() != Some(&0x00) {
            self.broken = true;
            return Err(DriverError::UnexpectedPacket.into());
        }
        Ok(())
    }

    /// `START TRANSACTION` (the driver's `TxOpts::default()`: the server's isolation level).
    pub async fn start_transaction(&mut self) -> Result<Transaction<'_>> {
        self.query_drop("START TRANSACTION").await?;
        Ok(Transaction {
            conn: self,
            done: false,
        })
    }
}

impl Conn {
    /// `START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY` under REPEATABLE READ: every read until the commit sees one point in time.
    pub async fn start_snapshot(&mut self) -> Result<Transaction<'_>> {
        self.query_drop("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await?;
        self.query_drop("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            .await?;
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
    pub async fn commit(mut self) -> Result<()> {
        self.conn.query_drop("COMMIT").await?;
        self.done = true;
        Ok(())
    }

    /// `ROLLBACK`.
    pub async fn rollback(mut self) -> Result<()> {
        self.conn.query_drop("ROLLBACK").await?;
        self.done = true;
        Ok(())
    }
}

fn parse_row(payload: &[u8], columns: Arc<[Column]>, binary: bool) -> std::io::Result<Row> {
    let mut input = ParseBuf(payload);
    let bitmap = if binary {
        if input.checked_eat_u8() != Some(0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid binary row header",
            ));
        }
        Some(input.parse::<NullBitmap<ServerSide, Cow<'_, [u8]>>>(columns.len())?)
    } else {
        None
    };
    let mut values = SecretValues(Vec::with_capacity(columns.len()));
    for (index, column) in columns.iter().enumerate() {
        let value = match &bitmap {
            Some(bitmap) if bitmap.is_null(index) => Value::NULL,
            Some(_) => {
                input
                    .parse::<ValueDeserializer<BinValue>>((column.column_type(), column.flags()))?
                    .0
            }
            None => input.parse::<ValueDeserializer<TextValue>>(())?.0,
        };
        values.0.push(value);
    }
    Ok(mysql_common::row::new_row(
        std::mem::take(&mut values.0),
        columns,
    ))
}

/// `row` as `T`; the driver's `from_row` panics (echoing the row) when it does not convert.
fn convert<T: FromRow>(row: Row) -> Result<T> {
    from_row_opt(row).map_err(|mut error| {
        for index in 0..error.0.len() {
            if let Some(mut value) = error.0.take::<Value, _>(index) {
                wipe_value(&mut value);
            }
        }
        DriverError::RowConversion(std::any::type_name::<T>()).into()
    })
}

fn auth_refused(error: busbar_contract::abi::sdk::chip::Refused) -> Error {
    Error::DriverError(DriverError::AuthRefused(error.to_string()))
}

#[cfg(test)]
#[path = "mysqlwire_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "mysqlwire_auth_tests.rs"]
mod auth_tests;
