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

pub fn code(
    secret: &str,
    algorithm: &str,
    digits: u32,
    period: u64,
    timestamp: u64,
) -> Result<Zeroizing<String>, String> {
    if ![6, 8].contains(&digits) || !(15..=120).contains(&period) {
        return Err("TOTP 参数无效".into());
    }
    let secret = normalize(secret)?;
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(secret.as_bytes())
            .map_err(|_| "BASE32 解码失败")?,
    );
    let counter = (timestamp / period).to_be_bytes();
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(&key).map_err(|_| "TOTP 密钥无效")?;
            mac.update(&counter);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let hash = Zeroizing::new(match algorithm {
        "SHA1" => digest!(sha1::Sha1),
        "SHA256" => digest!(sha2::Sha256),
        "SHA512" => digest!(sha2::Sha512),
        _ => return Err("TOTP 算法无效".into()),
    });
    let offset = (hash[hash.len() - 1] & 15) as usize;
    let value =
        u32::from_be_bytes(hash[offset..offset + 4].try_into().expect("HMAC offset")) & 0x7fffffff;
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        value % 10u32.pow(digits),
        width = digits as usize
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_vectors_and_base32_validation() {
        for (algorithm, size, expected) in [
            ("SHA1", 20, "94287082"),
            ("SHA256", 32, "46119246"),
            ("SHA512", 64, "90693936"),
        ] {
            let key = (0..size).map(|n| b"1234567890"[n % 10]).collect::<Vec<_>>();
            assert_eq!(
                &*code(&BASE32_NOPAD.encode(&key), algorithm, 8, 30, 59).unwrap(),
                expected
            );
        }
        assert!(normalize("not-valid!").is_err());
        assert!(normalize("MY======").is_err());
    }
}
