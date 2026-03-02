use crate::config::PasswordServiceConfig;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::utils::crypto;
use serde_json::json;
use std::env;

/// Fetch the database password from ICBC TECC service via HTTP POST,
/// then decrypt the salted SM4-CBC encrypted password.
pub async fn fetch_db_password(config: &PasswordServiceConfig) -> AuthResult<String> {
    let url = config.url.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.url not configured"
        )
    })?;
    let db_name = config.db_name.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.db_name not configured"
        )
    })?;
    let user_name = config.user_name.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.user_name not configured"
        )
    })?;
    let mode = config.mode.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.mode not configured"
        )
    })?;
    let service = config.service.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.service not configured"
        )
    })?;
    let app_name = config.app_name.as_ref().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "password_service.app_name not configured"
        )
    })?;

    let token = env::var("ICBC_TECC_TOKEN")
        .map_err(|_| crate::errno!(ErrorCode::InternalErr, "env ICBC_TECC_TOKEN not set"))?;
    let sm4_key_b64 = env::var("ICBC_SM4_KEY_B64")
        .map_err(|_| crate::errno!(ErrorCode::InternalErr, "env ICBC_SM4_KEY_B64 not set"))?;

    let sm4_key = crate::utils::tool::base64_decode(&sm4_key_b64)?;

    let body = json!({
        "mode": mode,
        "service": service,
        "appName": app_name,
        "param": {
            "dbName": db_name,
            "userName": user_name,
        },
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(url.as_str())
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

    let encrypted_b64 = resp_json["data"]["keyId"].as_str().ok_or_else(|| {
        crate::errno!(
            ErrorCode::InternalErr,
            "ICBC TECC response missing data.keyId field"
        )
    })?;
    log::info!("Get encrypted password from ICBC TECC service success.");

    let ciphertext = crate::utils::tool::base64_decode(encrypted_b64)?;

    let plaintext_bytes = crypto::sm4_cbc_salt_decrypt(&sm4_key, &ciphertext)?;

    let password = String::from_utf8(plaintext_bytes).map_err(|e| {
        crate::errno!(
            ErrorCode::CryptoErr,
            "decrypted password is not valid UTF-8: {}",
            e
        )
    })?;
    log::info!("Decrypted password from ICBC TECC service success.");

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
        let decrypted = crypto::sm4_cbc_salt_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            "my_secret_db_password"
        );
    }
}
