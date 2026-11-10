// SPDX-License-Identifier: Apache-2.0
use super::{Bytes, PasswordAt};
use zeroize::Zeroizing;
type Found = (Bytes, PasswordAt);
const TWO: &str = "a URL with one password (userinfo or `password=`, not both)";

pub(super) fn split_url(
    text: &str,
    scheme_end: usize,
    query: bool,
) -> Result<(String, Option<Found>), &'static str> {
    let head = &text[..scheme_end + 3];
    let rest = &text[scheme_end + 3..];
    let pre_query = rest.find('?').unwrap_or(rest.len());
    let strict = rest[..pre_query].rfind('@');
    let at = strict.or_else(|| {
        rest.rfind('@')
            .filter(|&a| !rest[..a].contains('/') && rest[..a].contains(':'))
    });
    let userinfo_at = match at {
        Some(a) if strict.is_some() && !rest[..a].contains(['/', '#']) => PasswordAt::Userinfo,
        _ => PasswordAt::UserinfoUnencoded,
    };
    let mut public = String::with_capacity(text.len());
    public.push_str(head);
    let mut password = None;
    let after = match at {
        Some(a) => {
            let userinfo = &rest[..a];
            match userinfo.split_once(':') {
                Some((user, pass)) => {
                    password = Some((decode(pass), userinfo_at));
                    public.push_str(user);
                    public.push('@');
                }
                None => {
                    public.push_str(userinfo);
                    public.push('@');
                }
            }
            &rest[a + 1..]
        }
        None => rest,
    };
    match after.split_once('?').filter(|_| query) {
        None => public.push_str(after),
        Some((path, query)) => {
            public.push_str(path);
            let (fragment_free, fragment) = match query.split_once('#') {
                Some((q, f)) => (q, Some(f)),
                None => (query, None),
            };
            let mut kept = Vec::new();
            for pair in fragment_free.split('&') {
                let named = pair.split_once('=').and_then(|(key, value)| {
                    match decode_form(key).as_slice() {
                        b"password" => Some(("password", value)),
                        b"pass" => Some(("pass", value)),
                        _ => None,
                    }
                });
                if let Some((name, v)) = named {
                    if password.is_some() {
                        return Err(TWO);
                    }
                    password = Some((decode_form(v), PasswordAt::Query(name)));
                } else {
                    kept.push(pair);
                }
            }
            if !kept.is_empty() {
                public.push('?');
                public.push_str(&kept.join("&"));
            }
            if let Some(f) = fragment {
                public.push('#');
                public.push_str(f);
            }
        }
    }
    Ok((public, password))
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_form(s: &str) -> Bytes {
    let spaced = Zeroizing::new(s.replace('+', " "));
    decode(&spaced)
}

fn decode(s: &str) -> Bytes {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}
