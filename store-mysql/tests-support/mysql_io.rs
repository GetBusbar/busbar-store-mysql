// SPDX-License-Identifier: Apache-2.0
//! The actual connector and TCP carrier used by this repository's live MySQL tests.
//! No MySQL protocol or connection-table implementation lives here.
use busbar_contract::conn::{ConnWake, DeclaredConns};
use busbar_contract::transport::{EgressTrust, TransportSettings};
use busbar_core_connector::doors::Dispatched;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use std::net::ToSocketAddrs;
use std::sync::{Arc, OnceLock};

fn reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("MySQL I/O reactor");
        let handle = runtime.handle().clone();
        std::thread::spawn(move || runtime.block_on(std::future::pending::<()>()));
        handle
    })
    .clone()
}
fn transport_dispatcher() -> &'static Arc<Dispatcher> {
    static ONE: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    ONE.get_or_init(|| {
        let dispatcher = Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        );
        dispatcher.install_runtime(reactor());
        dispatcher.install_io(busbar_core_connector::hostio::process());
        Arc::new(dispatcher)
    })
}
/// Bind the real TCP door and production connector. Private database addresses are intentional:
/// BUSBAR_TEST_MYSQL_URL names an operator-provisioned integration service.
pub fn host(wake: ConnWake, trust: EgressTrust) -> Arc<dyn DeclaredConns> {
    busbar_core_connector::io::install_process_reactor(reactor());
    let dispatcher = transport_dispatcher();
    let row = LinkedRow::of(busbar_transport_tcp::linked::door).expect("real TCP statement");
    let plugin = load_linked::<Transport>(
        &row,
        Bind {
            instance: Arc::from("mysql-test-tcp"),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("real TCP door loads");
    let door = Dispatched::open_on(
        plugin,
        &TransportSettings::default(),
        Arc::clone(dispatcher),
    )
    .expect("real TCP door opens");
    let transports = Transports::new(vec![Entry {
        door: Arc::new(door),
        alpn: Vec::new(),
    }])
    .expect("real TCP composes");
    let tls = busbar_core_connector::tls::client::build_client_config(&trust)
        .expect("MySQL TLS configuration");
    let judge = |target: &str,
                 _class: u32,
                 _done: Judged|
     -> Option<Result<std::net::SocketAddr, Verdict>> {
        Some(
            target
                .to_socket_addrs()
                .ok()
                .and_then(|mut addresses| addresses.next())
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    };
    Arc::new(Connector::serving(
        transports,
        Arc::new(judge),
        Some(Arc::new(tls)),
        wake,
    ))
}
