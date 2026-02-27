use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::utils::crypto;
use serde_json::json;
use std::env;

/// Fetch the database password from ICBC TECC service via HTTP POST,
/// then decrypt the SM4-CBC encrypted password.
pub async fn fetch_db_password(
    password_url: &str,
    db_name: &str,
    user_name: &str,
) -> AuthResult<String> {
    let token = env::var("ICBC_TECC_TOKEN")
        .map_err(|_| crate::errno!(ErrorCode::InternalErr, "env ICBC_TECC_TOKEN not set"))?;
    let sm4_key_b64 = env::var("SM4_KEY")
        .map_err(|_| crate::errno!(ErrorCode::InternalErr, "env SM4_KEY not set"))?;

    let sm4_key = crate::utils::tool::base64_decode(&sm4_key_b64)?;

    let body = json!({
        "mode": "online",
        "service": "dbSafeService",
        "appName": "F-TECC",
        "param": {
            "dbName": db_name,
            "userName": user_name,
        },
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(password_url)
        .header("token", &token)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            crate::errno!(
                ErrorCode::InternalErr,
                "HTTP request to ICBC TECC failed: {}",
                e
            )
        })?;

    if !resp.status().is_success() {
        return Err(crate::errno!(
            ErrorCode::InternalErr,
            "ICBC TECC service returned HTTP {}",
            resp.status()
        ));
    }

    let resp_json: serde_json::Value = resp.json().await.map_err(|e| {
        crate::errno!(
            ErrorCode::InternalErr,
            "failed to parse ICBC TECC response: {}",
            e
        )
    })?;

    let encrypted_hex = resp_json["data"]["keyId"].as_str().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "ICBC TECC response missing data.keyId field"
        )
    })?;

    let ciphertext = hex::decode(encrypted_hex).map_err(|e| {
        crate::errno!(
            ErrorCode::CryptoErr,
            "invalid password hex from ICBC TECC: {}",
            e
        )
    })?;

    let plaintext_bytes = crypto::sm4_cbc_salt_decrypt(&sm4_key, &ciphertext)?;

    let password = String::from_utf8(plaintext_bytes).map_err(|e| {
        crate::errno!(
            ErrorCode::CryptoErr,
            "decrypted password is not valid UTF-8: {}",
            e
        )
    })?;

    Ok(password)
}

#[cfg(test)]
mod tests {
    use crate::utils::crypto;

    #[test]
    fn test_decrypt_password_logic() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = b"my_secret_db_password";

        let ciphertext = crypto::sm4_cbc_salt_encrypt(&key, plaintext).unwrap();
        let encrypted_hex = hex::encode(&ciphertext);

        // Simulate what fetch_db_password does after getting the hex string
        let decoded = hex::decode(&encrypted_hex).unwrap();
        let decrypted = crypto::sm4_cbc_salt_decrypt(&key, &decoded).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            "my_secret_db_password"
        );
    }
}
