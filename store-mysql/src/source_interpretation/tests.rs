use super::*;
busbar_contract::own_seal!(Owner);
fn with_row(cells: &[Cell<'_>], call: impl FnOnce(Row<'_>)) {
    let bytes =
        busbar_contract::persistence::legacy_row::encode::<Owner>(cells, 1024 * 1024).unwrap();
    call(Row::decode(bytes.expose_own(&Owner::here())).unwrap());
}
#[test]
fn published_source_rows_preserve_original_evidence_and_native_shapes() {
    let bytes = include_bytes!("fixtures/mysql-1.5.5-rows.json");
    let manifest = include_str!("fixtures/mysql-1.5.5-MANIFEST.tsv");
    let digest = manifest
        .lines()
        .find_map(|line| line.strip_prefix("file\trows.json "))
        .unwrap();
    assert_eq!(
        busbar_contract::persistence::archive::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        digest
    );
    let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert!(data["credentials"].as_array().unwrap().is_empty());
    for table in ["api_keys", "usage_windows", "usage_metering", "audit_log"] {
        for original in data[table].as_array().unwrap() {
            let columns = original
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let json = columns
                .iter()
                .map(|name| match &original[*name] {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        Some(serde_json::to_vec(&original[*name]).unwrap())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let cells = columns
                .iter()
                .enumerate()
                .map(|(index, column)| match &original[*column] {
                    serde_json::Value::Null => Cell::Null,
                    serde_json::Value::String(s) => Cell::Text(s.as_bytes()),
                    serde_json::Value::Bool(value) => Cell::Integer(i64::from(*value)),
                    serde_json::Value::Number(n) => Cell::Integer(n.as_i64().unwrap()),
                    _ => Cell::Text(json[index].as_ref().unwrap()),
                })
                .collect::<Vec<_>>();
            let value =
                busbar_contract::persistence::legacy_row::encode::<Owner>(&cells, 1024 * 1024)
                    .unwrap();
            let original_digest =
                busbar_contract::persistence::archive::digest(value.expose_own(&Owner::here()));
            let source = busbar_contract::persistence::lifecycle::SourceRow {
                table: 0,
                native_key: busbar_contract::Secret::held(vec![1]),
                value,
            };
            let catalogue = busbar_contract::persistence::archive::Table {
                name: table.into(),
                columns: columns.iter().map(|v| (*v).to_owned()).collect(),
                native_layout: vec![1],
            };
            let chunk =
                super::super::interpret(3, &catalogue, &source, 1024 * 1024, &Owner::here())
                    .unwrap();
            assert_eq!(chunk.evidence[0].value_digest, original_digest);
            assert_eq!(chunk.evidence[0].native_key, source.native_key);
            assert_eq!(chunk.facts.len(), 1);
            assert!(chunk.complete);
            assert_eq!(chunk.sequence, 0);
        }
    }
}

#[test]
fn synthetic_mysql_dev_keeps_binary_identifiers_and_decimal_quantity() {
    let columns = USAGE
        .iter()
        .copied()
        .chain(["bucket_scope"])
        .collect::<Vec<_>>();
    let cells = [
        Cell::Integer(0),
        Cell::Blob(b"bucket"),
        Cell::Blob(b"m"),
        Cell::Integer(1),
        Cell::Integer(1),
        Cell::Text(b"170141183460469231731687303715884105"),
        Cell::Text(b"0"),
        Cell::Text(b"0"),
        Cell::Text(b"0"),
        Cell::Blob(b"key"),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Usage(cell) =
            decode(Profile::Dev7, "usage_windows", &columns, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            cell.ledger.total_input(),
            170141183460469231731687303715884105
        );
        assert_eq!(cell.ledger.requests, 1);
    });
}
