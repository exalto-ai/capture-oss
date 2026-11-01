use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

pub(crate) fn normalize_api_key(api_key: String) -> Result<Zeroizing<String>, String> {
    let api_key = Zeroizing::new(api_key);
    let normalized = Zeroizing::new(api_key.trim().to_owned());
    if normalized.len() < 8
        || normalized.len() > 512
        || !normalized.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("Enter a valid API key containing no spaces or line breaks.".into());
    }
    Ok(normalized)
}

pub(crate) fn sensitive_header(value: &[u8]) -> Result<HeaderValue, String> {
    let mut value = HeaderValue::from_bytes(value)
        .map_err(|_| "Enter a valid API key containing no spaces or line breaks.".to_string())?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_keys_never_echo_secret_values() {
        let bad = "sk-secret\ninvalid";
        assert!(
            !normalize_api_key(bad.into())
                .unwrap_err()
                .contains("sk-secret")
        );
        assert_eq!(
            &**normalize_api_key("  sk-test-credential  ".into()).unwrap(),
            "sk-test-credential"
        );
        assert!(
            sensitive_header(b"Bearer sk-test-credential")
                .unwrap()
                .is_sensitive()
        );
    }
}
