use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

pub fn normalize(value: &str) -> Result<Zeroizing<String>, String> {
    let normalized = Zeroizing::new(
        value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .trim_end_matches('=')
            .to_ascii_uppercase(),
    );
    let bytes = Zeroizing::new(
        BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| "2FA 密钥不是有效的 BASE32")?,
    );
    if !(10..=128).contains(&bytes.len()) {
        return Err("2FA 密钥长度必须为 80–1024 位".into());
    }
    Ok(normalized)
}

pub fn generate_secret() -> Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 10]);
    rand::rng().fill_bytes(&mut *bytes);
    Zeroizing::new(BASE32_NOPAD.encode(&*bytes))
}

pub fn code(secret: &str, period: u64, timestamp: u64) -> Result<Zeroizing<String>, String> {
    if !(1..=300).contains(&period) {
        return Err("网关 OTP 周期无效".into());
    }
    let secret = normalize(secret)?;
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(secret.as_bytes())
            .map_err(|_| "BASE32 解码失败")?,
    );
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).map_err(|_| "OTP 密钥无效")?;
    mac.update(&(timestamp / period).to_be_bytes());
    let hash = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let offset = (hash[hash.len() - 1] & 15) as usize;
    let value =
        u32::from_be_bytes(hash[offset..offset + 4].try_into().expect("HMAC offset")) & 0x7fffffff;
    Ok(Zeroizing::new(format!("{:06}", value % 1_000_000)))
}

pub fn adjusted_time(now_ms: u64, offset: i64) -> Result<u64, String> {
    let now = i64::try_from(now_ms / 1000).map_err(|_| "本机时间无效")?;
    now.checked_add(offset)
        .and_then(|time| u64::try_from(time).ok())
        .ok_or_else(|| "网关校时结果无效".into())
}

fn provisioning_uri(
    secret: &str,
    server: &str,
    username: &str,
    period: u64,
) -> Result<Zeroizing<String>, String> {
    if !(1..=300).contains(&period) {
        return Err("OTP 周期无效".into());
    }
    let secret = normalize(secret)?;
    let gateway = url::Url::parse(server).map_err(|_| "网关地址无效")?;
    let issuer = format!("Array {}", gateway.host_str().ok_or("网关地址无效")?);
    let mut uri = url::Url::parse("otpauth://totp/").expect("constant URI");
    uri.path_segments_mut()
        .map_err(|_| "OTP URI 无效")?
        .pop_if_empty()
        .push(&format!("{issuer}:{username}"));
    uri.query_pairs_mut()
        .append_pair("secret", &secret)
        .append_pair("issuer", &issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", &period.to_string());
    let uri = Zeroizing::new(uri.to_string());
    Ok(uri)
}
pub fn qr_svg(secret: &str, server: &str, username: &str, period: u64) -> Result<String, String> {
    let uri = provisioning_uri(secret, server, username, period)?;
    let qr = qrcode::QrCode::new(uri.as_bytes()).map_err(|_| "无法生成 OTP 二维码")?;
    Ok(qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(280, 280)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn array_sha1_codes_follow_rfc6238_and_gateway_period_bounds() {
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        for (time, expected) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1234567890, "005924"),
        ] {
            assert_eq!(&*code(&secret, 30, time).unwrap(), expected);
        }
        assert!(code(&secret, 1, 59).is_ok());
        assert!(code(&secret, 300, 59).is_ok());
        assert!(code(&secret, 0, 59).is_err());
        assert!(normalize("not-valid!").is_err());
        assert!(adjusted_time(10_000, -20).is_err());
        assert_eq!(adjusted_time(100_000, -20).unwrap(), 80);
        let seed = generate_secret();
        assert_eq!(seed.len(), 16);
        assert!(normalize(&seed).is_ok());
        let svg = qr_svg(&seed, "https://vpn.example.test", "用户+account", 60).unwrap();
        assert!(svg.contains("<svg"));
        assert!(!svg.contains(&*seed));
    }
    #[test]
    fn provisioning_uri_encodes_account_and_carries_the_gateway_period() {
        let uri = provisioning_uri(
            "JBSWY3DPEHPK3PXP",
            "https://vpn.example.test",
            "用户+account",
            90,
        )
        .unwrap();
        let uri = url::Url::parse(&uri).unwrap();
        assert_eq!(uri.scheme(), "otpauth");
        assert_eq!(uri.host_str(), Some("totp"));
        assert!(!uri.path().starts_with("//"));
        let params = uri
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(params["secret"], "JBSWY3DPEHPK3PXP");
        assert_eq!(params["period"], "90");
        assert_eq!(params["algorithm"], "SHA1");
        assert_eq!(params["digits"], "6");
        assert_eq!(params["issuer"], "Array vpn.example.test");
    }
}
