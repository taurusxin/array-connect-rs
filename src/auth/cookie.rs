use crate::{Result, VpnError};
use cookie_store::CookieError;

pub(super) fn invalid_set_cookie(error: CookieError) -> VpnError {
    // Use fixed categories only; server-controlled names, values and attributes
    // may contain credentials and must not be included in errors or logs.
    let reason = match error {
        CookieError::Parse => "malformed cookie",
        CookieError::DomainMismatch => "domain mismatch",
        CookieError::Expired => "expired cookie",
        CookieError::NonHttpScheme => "non-HTTP cookie origin",
        CookieError::NonRelativeScheme => "cookie origin has no host",
        CookieError::PublicSuffix => "public suffix domain",
        CookieError::UnspecifiedDomain => "missing cookie domain",
    };
    tracing::warn!(reason, "Set-Cookie rejected (value redacted)");
    VpnError::Protocol(format!("invalid Set-Cookie: {reason}"))
}

pub(super) fn validate_cookie(cookie: &str) -> Result<()> {
    if cookie.len() > 16384 || cookie.bytes().any(|c| c.is_ascii_control()) {
        return Err(VpnError::Config("invalid Cookie header".into()));
    }
    let mut session = false;
    for pair in cookie.split(';') {
        let (name, value) = pair
            .trim()
            .split_once('=')
            .ok_or_else(|| VpnError::Config("Cookie must contain name=value pairs".into()))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(VpnError::Config("invalid Cookie name".into()));
        }
        session |= name.starts_with("ANsession") && !value.is_empty();
    }
    if !session {
        return Err(VpnError::Config(
            "Cookie must contain a nonempty ANsession entry".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auth::session::AuthSession, transport::http::Response};
    use url::Url;

    fn response(cookies: &[&str]) -> Response {
        Response {
            status: 200,
            headers: cookies
                .iter()
                .map(|cookie| ("Set-Cookie".into(), (*cookie).into()))
                .collect(),
        }
    }

    #[test]
    fn expired_cookie_cleanup_on_a_fresh_session_keeps_processing_the_response() {
        let url = Url::parse("https://vpn.example.test/login").unwrap();
        let mut auth = AuthSession::new();
        for _ in 0..3 {
            auth.update(
                &response(&[
                    "old=; Max-Age=0; Path=/; Secure",
                    "older=nonempty; Max-Age=-1; Path=/; Secure",
                    "oldest=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure",
                    "ANsessionnew=current; Path=/; Secure",
                ]),
                &url,
            )
            .unwrap();
            assert_eq!(auth.cookie_header(&url), "ANsessionnew=current");
        }
    }

    #[test]
    fn cookie_deletion_removes_jar_and_explicit_session_copies() {
        let url = Url::parse("https://vpn.example.test/portal/login").unwrap();
        let tunnel = Url::parse("https://vpn.example.test/vpntunnel").unwrap();
        for stored_in_jar in [false, true] {
            for attributes in ["Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"] {
                let mut auth = AuthSession::new();
                if stored_in_jar {
                    auth.update(&response(&["ANsessionold=old; Path=/portal; Secure"]), &url)
                        .unwrap();
                }
                auth.set_cookie("ANsessionold=old; ANsessionkeep=keep".into())
                    .unwrap();
                let deletion =
                    format!("ANsessionold=nonempty-expired; {attributes}; Path=/portal; Secure");
                for _ in 0..2 {
                    auth.update(&response(&[&deletion]), &url).unwrap();
                    assert_eq!(auth.cookie_header(&url), "ANsessionkeep=keep");
                    assert_eq!(auth.cookie_header(&tunnel), "ANsessionkeep=keep");
                }
                auth.update(
                    &response(&["ANsessionkeep=rotated; Path=/portal; Secure"]),
                    &url,
                )
                .unwrap();
                assert_eq!(auth.cookie_header(&tunnel), "ANsessionkeep=rotated");
            }
        }
    }

    #[test]
    fn rejected_cookies_keep_domain_checks_and_only_expose_a_fixed_error_category() {
        let url = Url::parse("https://vpn.example.test/login").unwrap();
        for (header, reason) in [
            ("SECRET_COOKIE_VALUE; Path=/", "malformed cookie"),
            ("=SECRET_COOKIE_VALUE; Path=/", "malformed cookie"),
            (
                "ANsession=SECRET_COOKIE_VALUE; Domain=private.example.invalid; Max-Age=0; Path=/",
                "domain mismatch",
            ),
        ] {
            let mut auth = AuthSession::new();
            auth.set_cookie("ANsessionkeep=previous".into()).unwrap();
            let error = auth
                .update(&response(&[header]), &url)
                .unwrap_err()
                .to_string();
            assert!(error.contains(reason));
            assert!(!error.contains("SECRET_COOKIE_VALUE"));
            assert!(!error.contains("private.example.invalid"));
            assert_eq!(auth.cookie_header(&url), "ANsessionkeep=previous");
        }
    }

    #[test]
    fn cookie_validation() {
        assert!(validate_cookie("ANsession123=secret; other=a=b").is_ok());
        for cookie in [
            "DSID=x",
            "ANsession=",
            "ANsession=x\r\nInjected: x",
            "ANsession=x; broken",
        ] {
            assert!(validate_cookie(cookie).is_err());
        }
    }
}
