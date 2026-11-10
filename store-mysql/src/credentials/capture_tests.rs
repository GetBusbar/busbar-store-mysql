// SPDX-License-Identifier: Apache-2.0
// Native capture assertions transferred from the SDK. Secret bytes are observed only by test-seal.
use super::*;
use busbar_contract::abi::sdk::cred::settings;
use busbar_contract::abi::sdk::test_support::chip::observe_credential;
fn password(url: &CredUrl) -> Option<Vec<u8>> {
    url.password().map(|value| {
        let mut out = Vec::new();
        observe_credential(value, |bytes| out.extend_from_slice(bytes));
        out
    })
}
#[test]
fn conflicting_userinfo_and_query_passwords_are_refused() {
    assert!(CredUrl::parse("mysql://u:a@h?password=b").is_err());
}
#[test]
fn redaction_preserves_diagnostics_and_literal_case() {
    let p = CredUrl::parse("mysql://u:p%252fA@h/db").unwrap();
    assert_eq!(
        p.redact_echo("server says p%2fA or p%252fA; p%2FA stays"),
        "server says <redacted> or <redacted>; p%2FA stays"
    );
    let p = CredUrl::parse("mysql://u:p%2FA@h/db").unwrap();
    assert_eq!(
        p.redact_echo("p/a p/A p%2fA p%2FA"),
        "p/a <redacted> <redacted> <redacted>"
    );
    assert_eq!(
        CredUrl::parse("mysql://u:@h/db")
            .unwrap()
            .redact_echo("diagnostic"),
        "diagnostic"
    );
}

#[test]
fn mysql_typed_settings_trim_before_password_and_floor_capture() {
    let p: MysqlUrl = settings(br#""  mysql://u@h/db?secure_auth=false&password=pw   ""#).unwrap();
    assert_eq!(password(&p.0).as_deref(), Some(&b"pw"[..]));
    assert!(p.0.policy.old);
    assert_eq!(p.0.public(), "mysql://u@h/db?secure_auth=false");
}

#[test]
fn a_percent_encoded_password_key_in_a_url_query_is_still_the_password() {
    for key in ["pass%77ord", "%70ass"] {
        let p = CredUrl::parse(&format!("mysql://u@h/db?{key}=s3cret")).unwrap();
        assert_eq!(password(&p).as_deref(), Some(&b"s3cret"[..]));
        assert_eq!(p.public(), "mysql://u@h/db");
        assert!(!p.redact_echo("server rejected s3cret").contains("s3cret"));
        assert!(CredUrl::parse(&format!("mysql://u:other@h/db?{key}=s3cret")).is_err());
    }
}
