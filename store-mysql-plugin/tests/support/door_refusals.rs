// SPDX-License-Identifier: Apache-2.0
//! Malformed metadata over the actual MySQL door; no substitute store implementation.
use super::*;
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{Door, DoorParts, Statement};
use busbar_contract::abi::mechanism::{rendering, KindCode};
use busbar_plugin_loader::dispatch::load::rendering_of_raw;
use busbar_plugin_loader::dispatch::{Kind, LoadError};
use std::sync::atomic::{AtomicPtr, Ordering};

static MUTATED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
extern "C" fn mutated() -> *const Door {
    MUTATED.load(Ordering::SeqCst)
}
extern "C" fn real() -> *const Door {
    busbar_store_mysql::door()
}
// Used by one sequential test only. The real table and all newly allocated metadata remain static.
fn restate(parts: DoorParts) {
    // SAFETY: only ABI/layout numbers or a whole leaked Statement change. Every nested pointer
    // otherwise comes from the actual product's immutable static door.
    let door = unsafe { Door::__from_parts(parts) };
    MUTATED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
}
#[test]
fn incompatible_metadata_is_refused_before_any_store_slot_runs() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let (honest, d) = linked();
    drop(honest);
    drop(d);
    let (honest, d) = dropped(&lib, &stated);
    drop(honest);
    drop(d);
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let original = busbar_store_mysql::door().parts();
    let kind = KindCode::Store;
    let abi = kind.abi_version();
    assert_eq!(original.kind_abi, abi);
    for version in [abi + 1, abi.wrapping_sub(1)] {
        restate(DoorParts {
            kind_abi: version,
            ..original
        });
        let expected = LoadError::KindAbi {
            kind,
            door: version,
            host: abi,
        };
        assert_eq!(rendering_of_raw(mutated).err(), Some(expected.clone()));
        let error = LinkedRow::of_raw(mutated)
            .and_then(|row| load_linked::<Store>(&row, bind(&d)))
            .err()
            .unwrap();
        assert_eq!(error, expected);
        assert!(error.to_string().contains("rebuild"));
        let mut manifest = stated.clone();
        let at = rendering::RENDERING_MAGIC.len() + 8;
        manifest[at..at + 4].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            load_dropped::<Store>(&lib, &manifest, bind(&d)).err(),
            Some(LoadError::ManifestKindAbi {
                stated: version,
                host: abi
            })
        );
    }
    let layout = kind.layout_fingerprint();
    assert_eq!(original.layout, layout);
    for fingerprint in [layout ^ 1, 0] {
        restate(DoorParts {
            layout: fingerprint,
            ..original
        });
        let error = rendering_of_raw(mutated).unwrap_err();
        let LoadError::KindLayout {
            kind: said,
            stated: written,
            host,
            ..
        } = &error
        else {
            panic!("{error:?}")
        };
        assert_eq!((*said, *written, *host), (kind, fingerprint, layout));
        assert!(error
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let row = LinkedRow {
            statement: stated.clone(),
            door: mutated,
        };
        assert_eq!(
            load_linked::<Store>(&row, bind(&d)).err(),
            Some(error.clone())
        );
        assert_eq!(
            LinkedRow::of_raw(mutated)
                .and_then(|row| load_linked::<Store>(&row, bind(&d)))
                .err(),
            Some(error)
        );
    }
    // SAFETY: the actual door's validated Statement is immutable static product data.
    let statement = unsafe { original.statement.read_unaligned() };
    const VERSION: &str = "0.0.0-conformance-restated";
    let changed = Box::leak(Box::new(Statement {
        version: AbiStr {
            ptr: VERSION.as_ptr(),
            len: VERSION.len(),
        },
        ..statement
    }));
    restate(DoorParts {
        statement: changed,
        ..original
    });
    let lying = rendering_of_raw(mutated).unwrap();
    rendering::read(&lying).unwrap();
    assert_ne!(lying, stated);
    let row = LinkedRow {
        statement: lying.clone(),
        door: real,
    };
    assert_eq!(
        load_linked::<Store>(&row, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Store>(&lib, &lying, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    let row = LinkedRow {
        statement: stated,
        door: mutated,
    };
    assert_eq!(
        load_linked::<Store>(&row, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
}
fn wrong<K: Kind>() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let row = LinkedRow::of(busbar_store_mysql::door).unwrap();
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let want = Some(LoadError::ManifestKind {
        stated: KindCode::Store,
        want: K::CODE,
    });
    assert_eq!(load_linked::<K>(&row, bind(&d)).err(), want);
    assert_eq!(load_dropped::<K>(&lib, &stated, bind(&d)).err(), want);
}
#[test]
fn every_other_kind_refuses_the_actual_store_in_both_deliveries() {
    use busbar_plugin_loader::dispatch::kinds::{
        auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, transport::Transport,
    };
    wrong::<Auth>();
    wrong::<Export>();
    wrong::<Hook>();
    wrong::<Plane>();
    wrong::<Secret>();
    wrong::<Transport>();
}
#[test]
fn networked_store_requires_a_connection_table_and_can_be_probed() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let row = LinkedRow::of(busbar_store_mysql::door).unwrap();
    let facts = rendering::read(&stated).unwrap();
    let expected = LoadError::NoConnectionTable {
        plugin: facts.name.clone(),
        needs: facts.needs.len(),
    };
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = || Bind {
        conns: ConnTable::NoNeeds,
        ..bind(&d)
    };
    let error = load_linked::<Store>(&row, bind()).err().unwrap();
    assert_eq!(error, expected);
    assert!(error
        .to_string()
        .contains(&format!("plugin '{}'", facts.name)));
    assert_eq!(
        load_dropped::<Store>(&lib, &stated, bind()).err(),
        Some(expected)
    );
    load_linked::<Store>(
        &row,
        Bind {
            conns: ConnTable::Probe,
            ..bind()
        },
    )
    .expect("metadata probe needs no network");
}
