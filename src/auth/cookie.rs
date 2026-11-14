use crate::{Result, VpnError};

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
