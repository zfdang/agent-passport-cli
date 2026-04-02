use kitepass_api_client::{
    AgentProof, AuthPollRequest, DeviceCodeRequest, ImportAad, PassportClient, SignRequest,
    SigningMode, UploadWalletCiphertextRequest, ValidateSignIntentRequest,
};
use kitepass_crypto::hpke::{generate_recipient_keypair, seal_to_hex, IMPORT_ENCRYPTION_SCHEME};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_login_device_flow() {
    let mock_server = MockServer::start().await;

    // Mock device-code request
    Mock::given(method("POST"))
        .and(path("/v1/owner-auth/device-code"))
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
        .and(path("/v1/owner-auth/poll/dev_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token_mock_123",
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri()).expect("passport client should initialize");

    let device_res = client
        .request_device_code(&DeviceCodeRequest::default())
        .await
        .unwrap();
    assert_eq!(device_res.user_code, "USER-CODE");

    let poll_res = client
        .poll_device_code(&device_res.device_code, &AuthPollRequest::default())
        .await
        .unwrap();
    assert_eq!(poll_res.access_token.unwrap(), "token_mock_123");
}

#[tokio::test]
async fn test_wallet_hybrid_import() {
    let mock_server = MockServer::start().await;

    let vault_keypair = generate_recipient_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import-sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_999",
            "status": "awaiting_upload",
            "vault_signer_instance_id": "vs_dev_1",
            "vault_signer_attestation_endpoint": format!("{}/attest/import/sess_999", mock_server.uri()),
            "import_encryption_scheme": IMPORT_ENCRYPTION_SCHEME,
            "vault_signer_identity": {
                "instance_id": "vs_dev_1",
                "tee_type": "aws_nitro_enclaves_dev",
                "expected_measurements": {
                    "pcr0": "dev-pcr0",
                    "pcr1": "dev-pcr1",
                    "pcr2": "dev-pcr2"
                },
                "measurement_profile": {
                    "profile_id": "aws-nitro-dev-v1",
                    "version": 1
                },
                "reviewed_build": {
                    "build_id": "vault-signer-dev-reviewed-build-v1",
                    "build_digest": "sha256:dev-reviewed-build-v1",
                    "build_source": "apps/vault-signer",
                    "security_model_ref": "docs/public-security-model.md#attestation-auditability"
                },
                "authorization_model": "dual_sign_authorization_tee_signer"
            },
            "channel_binding": {
                "owner_id": "own_dev",
                "owner_session_id": "oas_dev",
                "request_id": "req_dev"
            },
            "expires_at": "2026-03-31T00:10:00Z"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/attest/import/sess_999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_999",
            "vault_signer_instance_id": "vs_dev_1",
            "attestation_bundle": serde_json::json!({
                "instance_id": "vs_dev_1",
                "pcr0": "dev-pcr0",
                "pcr1": "dev-pcr1",
                "pcr2": "dev-pcr2",
                "endpoint_binding": "binding_dev",
                "user_data": {
                    "document_version": 1,
                    "import_session_id": "sess_999",
                    "public_api_scope": "wallet_import_attestation",
                    "authorization_model": "dual_sign_authorization_tee_signer",
                    "import_encryption_scheme": IMPORT_ENCRYPTION_SCHEME,
                    "measurement_profile_id": "aws-nitro-dev-v1",
                    "measurement_profile_version": 1,
                    "reviewed_build_id": "vault-signer-dev-reviewed-build-v1",
                    "reviewed_build_digest": "sha256:dev-reviewed-build-v1",
                    "build_source": "apps/vault-signer",
                    "security_model_ref": "docs/public-security-model.md#attestation-auditability"
                }
            }).to_string(),
            "import_encryption_scheme": IMPORT_ENCRYPTION_SCHEME,
            "import_public_key": vault_keypair.public_key_hex,
            "endpoint_binding": "binding_dev"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import-sessions/sess_999/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operation_id": "op_123",
            "session_id": "sess_999",
            "status": "imported",
            "wallet_id": "wal_123"
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri())
        .expect("passport client should initialize")
        .with_token("valid_token".to_string());

    let session_res = client
        .create_import_session(
            "base",
            Some("test-wallet".to_string()),
            "idem_123".to_string(),
        )
        .await
        .unwrap();

    let attestation = client
        .fetch_import_attestation(&session_res.vault_signer_attestation_endpoint)
        .await
        .unwrap();

    let aad = ImportAad {
        owner_id: session_res.channel_binding.owner_id.clone(),
        owner_session_id: session_res.channel_binding.owner_session_id.clone(),
        request_id: session_res.channel_binding.request_id.clone(),
        vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
    };
    let info = serde_json::to_vec(&serde_json::json!({
        "document_version": 1,
        "import_session_id": session_res.session_id,
        "vault_signer_instance_id": session_res.vault_signer_instance_id,
        "endpoint_binding": attestation.endpoint_binding,
        "public_api_scope": "wallet_import_attestation",
        "authorization_model": "dual_sign_authorization_tee_signer",
        "import_encryption_scheme": IMPORT_ENCRYPTION_SCHEME,
        "measurement_profile_id": "aws-nitro-dev-v1",
        "measurement_profile_version": 1,
        "reviewed_build_id": "vault-signer-dev-reviewed-build-v1",
        "reviewed_build_digest": "sha256:dev-reviewed-build-v1",
        "build_source": "apps/vault-signer",
        "security_model_ref": "docs/public-security-model.md#attestation-auditability"
    }))
    .unwrap();
    let aad_bytes = serde_json::to_vec(&aad).unwrap();
    let sealed = seal_to_hex(
        &attestation.import_public_key,
        &info,
        &aad_bytes,
        b"my_secret_mnemonic",
    )
    .unwrap();

    let import_res = client
        .upload_wallet_ciphertext(
            &session_res.session_id,
            &UploadWalletCiphertextRequest {
                vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
                encapsulated_key: sealed.encapsulated_key_hex,
                ciphertext: sealed.ciphertext_hex,
                aad,
            },
        )
        .await
        .unwrap();
    assert_eq!(import_res.wallet_id.as_deref(), Some("wal_123"));
}

#[tokio::test]
async fn test_owner_query_surfaces() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/wallets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [{
                "wallet_id": "wal_123",
                "owner_id": "own_dev",
                "chain_family": "evm",
                "status": "active",
                "key_blob_ref": "vault://wallets/wal_123",
                "key_version": 1,
                "created_at": "2026-03-29T00:00:00Z",
                "updated_at": "2026-03-29T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/agent-access-keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_keys": [{
                "access_key_id": "aak_123",
                "owner_id": "own_dev",
                "public_key": "abcd",
                "key_alg": "ed25519",
                "key_address": "ed25519:abcd",
                "status": "active",
                "expires_at": "2027-03-29T00:00:00Z",
                "created_at": "2026-03-29T00:00:00Z",
                "updated_at": "2026-03-29T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/agent-access-keys/aak_123/bindings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bindings": [{
                "binding_id": "bind_123",
                "access_key_id": "aak_123",
                "wallet_id": "wal_123",
                "policy_id": "pol_123",
                "policy_version": 1,
                "status": "active",
                "is_default": true,
                "selection_priority": 0
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/agent-access-keys/aak_123/usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "usage": {
                "binding_id": "bind_123",
                "policy_id": "pol_123",
                "policy_version": 1,
                "wallet_id": "wal_123",
                "access_key_id": "aak_123",
                "lifetime_spent": "10",
                "daily_window_started_at": "2026-03-29T00:00:00Z",
                "daily_spent": "5",
                "rolling_window_started_at": "2026-03-29T00:00:00Z",
                "rolling_spent": "5",
                "last_consumed_request_id": "req_123",
                "updated_at": "2026-03-29T00:00:00Z"
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policies": [{
                "policy_id": "pol_123",
                "binding_id": "bind_123",
                "wallet_id": "wal_123",
                "access_key_id": "aak_123",
                "allowed_chains": ["eip155:8453"],
                "allowed_actions": ["transaction"],
                "max_single_amount": "100",
                "max_daily_amount": "500",
                "allowed_destinations": ["0xabc"],
                "valid_from": "2026-03-29T00:00:00Z",
                "valid_until": "2027-03-29T00:00:00Z",
                "state": "active",
                "version": 1
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/audit-events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{
                "event_id": "evt_123",
                "action": "signing_succeeded",
                "trace_id": "trace_123",
                "request_id": "req_123",
                "wallet_id": "wal_123",
                "access_key_id": "aak_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xdeadbeef",
                "outcome": "success",
                "policy_id": "pol_123",
                "policy_version": 1,
                "permit_id": "permit_123",
                "enclave_receipt": "receipt_123",
                "previous_event_hash": "root",
                "timestamp": "2026-03-29T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/audit-events/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "event_count": 1,
            "latest_event_id": "evt_123"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/operations/op_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operation_id": "op_123",
            "operation_type": "wallet_import",
            "request_id": "req_123",
            "status": "completed",
            "resource_type": "wallet",
            "resource_id": "wal_123",
            "error_code": null,
            "created_at": "2026-03-29T00:00:00Z",
            "updated_at": "2026-03-29T00:00:00Z",
            "poll_after_ms": null
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri())
        .expect("passport client should initialize")
        .with_token("valid_token".to_string());

    let wallets = client.list_wallets().await.unwrap();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].wallet_id, "wal_123");

    let access_keys = client.list_access_keys().await.unwrap();
    assert_eq!(access_keys.len(), 1);
    assert_eq!(access_keys[0].access_key_id, "aak_123");

    let bindings = client.list_bindings("aak_123").await.unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].policy_id, "pol_123");

    let usage = client
        .get_access_key_usage("aak_123")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.daily_spent, "5");

    let policies = client.list_policies().await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].policy_id, "pol_123");

    let events = client.list_audit_events(None).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "evt_123");

    let verify = client.verify_audit_chain().await.unwrap();
    assert!(verify.valid);

    let operation = client.get_operation("op_123").await.unwrap();
    assert_eq!(operation.status, "completed");
}

#[tokio::test]
async fn test_agent_signing_surfaces() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_123",
            "access_key_id": "aak_123",
            "session_nonce": "nonce_123",
            "status": "active",
            "expires_at": "2026-03-29T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_123",
            "valid": true,
            "resolved_wallet_id": "wal_123",
            "policy_id": "pol_123",
            "policy_version": 1,
            "normalized": {
                "wallet_id": "wal_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xdeadbeef",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/signatures"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_123",
            "status": "succeeded",
            "signature": "0xwalletsig",
            "enclave_receipt": "0xreceipt",
            "operation_id": null,
            "poll_after_ms": null
        })))
        .mount(&mock_server)
        .await;

    let client = PassportClient::new(mock_server.uri()).expect("passport client should initialize");
    let session = client.create_session("aak_123").await.unwrap();
    assert_eq!(session.session_nonce, "nonce_123");

    let validate = client
        .validate_sign_intent(&ValidateSignIntentRequest {
            request_id: "req_123".to_string(),
            wallet_id: None,
            wallet_selector: Some("auto".to_string()),
            access_key_id: "aak_123".to_string(),
            chain_id: "eip155:8453".to_string(),
            signing_type: "transaction".to_string(),
            payload: "0xdeadbeef".to_string(),
            destination: "0xabc".to_string(),
            value: "10".to_string(),
        })
        .await
        .unwrap();
    assert!(validate.valid);
    assert_eq!(validate.resolved_wallet_id, "wal_123");

    let sign = client
        .submit_signature(&SignRequest {
            request_id: "req_123".to_string(),
            idempotency_key: "idem_123".to_string(),
            wallet_id: "wal_123".to_string(),
            access_key_id: "aak_123".to_string(),
            chain_id: "eip155:8453".to_string(),
            signing_type: "transaction".to_string(),
            mode: SigningMode::SignatureOnly,
            payload: "0xdeadbeef".to_string(),
            destination: "0xabc".to_string(),
            value: "10".to_string(),
            agent_proof: AgentProof {
                access_key_id: "aak_123".to_string(),
                session_nonce: "nonce_123".to_string(),
                signature: "0xagentsig".to_string(),
            },
        })
        .await
        .unwrap();
    assert_eq!(sign.signature.as_deref(), Some("0xwalletsig"));
}
