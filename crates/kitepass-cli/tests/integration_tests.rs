use kitepass_api_client::PassportClient;
use kitepass_crypto::ecdh::{EphemeralKey, parse_public_key};
use kitepass_crypto::envelope::Envelope;
use tokio;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_login_device_flow() {
    let mock_server = MockServer::start().await;

    // Mock device-code request
    Mock::given(method("POST"))
        .and(path("/v1/owner/auth/device-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev_123",
            "user_code": "USER-CODE",
            "verification_uri": "https://kitepass.ai/activate",
            "expires_in": 300,
            "interval": 1
        })))
        .mount(&mock_server)
        .await;

    // Mock poll request
    Mock::given(method("POST"))
        .and(path("/v1/owner/auth/poll"))
        .and(body_partial_json(
            serde_json::json!({"device_code": "dev_123"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token_mock_123",
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri());

    let device_res = client.request_device_code().await.unwrap();
    assert_eq!(device_res.user_code, "USER-CODE");

    let poll_res = client
        .poll_device_code(&device_res.device_code)
        .await
        .unwrap();
    assert_eq!(poll_res.access_token.unwrap(), "token_mock_123");
}

#[tokio::test]
async fn test_wallet_hybrid_import() {
    let mock_server = MockServer::start().await;

    let vault_secret = EphemeralKey::generate();
    let vault_pubkey = vault_secret.public_key();
    let vault_pubkey_hex = hex::encode(vault_pubkey.as_bytes());

    let vault_nonce = [4u8; 32];
    let vault_nonce_hex = hex::encode(vault_nonce);

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import-sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_999",
            "vault_signer_url": "https://vault.kitepass.ai",
            "vault_signer_pubkey": vault_pubkey_hex,
            "vault_nonce": vault_nonce_hex,
            "attestation_doc": "fake-doc",
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet_id": "wal_123",
            "status": "imported",
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri()).with_token("valid_token".to_string());

    let session_res = client
        .create_import_session("base", Some("test-wallet".to_string()))
        .await
        .unwrap();

    // Simulate CLI encryption step
    let parsed_vault_pk = parse_public_key(&session_res.vault_signer_pubkey).unwrap();
    let parsed_vault_nonce = parse_public_key(&session_res.vault_nonce).unwrap();

    let ephemeral_key = EphemeralKey::generate();
    let shared_secret = ephemeral_key.diffie_hellman(&parsed_vault_pk);

    let ciphertext = Envelope::encrypt(
        &shared_secret,
        &parsed_vault_pk,
        &parsed_vault_nonce,
        b"my_secret_mnemonic",
    )
    .unwrap();

    let mut payload = Vec::new();
    payload.extend_from_slice(ephemeral_key.public_key().as_bytes());
    payload.extend(ciphertext);

    // Provide to `/import`
    let import_res = client
        .upload_wallet_ciphertext(&session_res.session_id, &hex::encode(payload))
        .await
        .unwrap();
    assert_eq!(import_res.wallet_id, "wal_123");
}
