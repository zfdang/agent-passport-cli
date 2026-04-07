use assert_cmd::Command;
use kitepass_config::{CliConfig, LocalPassportRecord, LocalPassportRegistry};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::{CryptoEnvelope, PassportToken};
use kitepass_crypto::hpke::{generate_recipient_keypair, IMPORT_ENCRYPTION_SCHEME};
use predicates::str::contains;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_COMBINED_SECRET: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn config_paths(tempdir: &TempDir) -> Vec<std::path::PathBuf> {
    vec![tempdir.path().join(".kitepass").join("config.toml")]
}

fn passports_paths(tempdir: &TempDir) -> Vec<std::path::PathBuf> {
    vec![tempdir.path().join(".kitepass").join("passports.toml")]
}

fn write_config(tempdir: &TempDir, api_url: Option<&str>, access_token: Option<&str>) {
    let config = CliConfig {
        api_url: api_url.map(str::to_string),
        default_chain: None,
        access_token: access_token.map(str::to_string),
        encrypted_access_token: None,
    };

    for path in config_paths(tempdir) {
        config.save(&path).expect("config should save");
    }
}

fn newest_existing_path(
    paths: impl IntoIterator<Item = std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    paths
        .into_iter()
        .filter(|path| path.exists())
        .max_by_key(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        })
}

fn load_saved_config(tempdir: &TempDir) -> CliConfig {
    let path = newest_existing_path(config_paths(tempdir)).expect("expected CLI config to exist");
    CliConfig::load(&path).expect("config should load")
}

fn load_saved_passports(tempdir: &TempDir) -> LocalPassportRegistry {
    let Some(path) = newest_existing_path(passports_paths(tempdir)) else {
        return LocalPassportRegistry::default();
    };
    LocalPassportRegistry::load(&path).expect("local passport registry should load")
}

fn write_passports(tempdir: &TempDir, registry: &LocalPassportRegistry) {
    for path in passports_paths(tempdir) {
        registry
            .save(&path)
            .expect("local passport registry should save");
    }
}

fn encrypted_passport_from_key(passport_id: &str, key: &AgentKey) -> LocalPassportRecord {
    let pem = key.export_pem().expect("key should export");
    LocalPassportRecord {
        passport_id: passport_id.to_string(),
        public_key_hex: key.public_key_hex(),
        encrypted_key: CryptoEnvelope::encrypt(pem.as_bytes(), TEST_COMBINED_SECRET)
            .expect("key should encrypt"),
    }
}

fn encrypted_passport(passport_id: &str) -> LocalPassportRecord {
    let key = AgentKey::generate();
    encrypted_passport_from_key(passport_id, &key)
}

fn cli_command(tempdir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("kitepass").expect("binary should build");
    command
        .env("XDG_CONFIG_HOME", tempdir.path())
        .env("HOME", tempdir.path());
    command
}

#[test]
fn status_shows_not_logged_in_without_session() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");

    cli_command(&tempdir)
        .args(["--json", "status"])
        .assert()
        .success()
        .stdout(contains("\"logged_in\": false"))
        .stdout(contains("\"api_url\":"))
        .stdout(contains("\"local_passport_keys\": 0"))
        .stdout(contains("\"config_dir\":"));
}

#[tokio::test]
async fn status_shows_logged_in_with_session() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![encrypted_passport("agp_one"), encrypted_passport("agp_two")],
        },
    );

    cli_command(&tempdir)
        .args(["--json", "status"])
        .assert()
        .success()
        .stdout(contains("\"logged_in\": true"))
        .stdout(contains("\"local_passport_keys\": 2"));
}

#[test]
fn status_text_mode_shows_human_readable_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");

    cli_command(&tempdir)
        .args(["status"])
        .assert()
        .success()
        .stdout(contains("Not logged in"));
}

#[test]
fn wallet_list_requires_login_with_stable_exit_code() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");

    cli_command(&tempdir)
        .args(["wallet", "list"])
        .assert()
        .failure()
        .code(3)
        .stderr(contains("Please run `kitepass login` first"));
}

#[test]
fn passport_create_dry_run_emits_json_without_writing_keys() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    write_config(
        &tempdir,
        Some("https://api.example.invalid"),
        Some("principal-token"),
    );

    cli_command(&tempdir)
        .args(["--json", "--dry-run", "passport", "create"])
        .assert()
        .success()
        .stdout(contains("\"dry_run\": true"))
        .stdout(contains("\"action\": \"passport.create\""))
        .stdout(contains("\"local_storage_path\": "))
        .stdout(contains("passports.toml"));

    assert!(
        !tempdir.path().join(".kitepass").join("keys").exists(),
        "dry-run should not materialize key files"
    );
}

#[tokio::test]
async fn passport_create_emits_clean_json_and_persists_encrypted_passport_key() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/passports:prepare"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "intent_id": "intent_123",
            "intent_hash": "hash_123",
            "approval_url": "https://kitepass.xyz/approve/intent_123",
            "approval_status": "pending_principal_step_up",
            "approval_expires_at": "2026-04-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/provisioning-intents/intent_123/approve"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "principal_approval_id": "oa_123",
            "record_type": "principal_approval_record",
            "record_version": 1,
            "principal_account_id": "pac_dev",
            "intent_id": "intent_123",
            "intent_hash": "hash_123",
            "operation": "create_passport",
            "approval_method": "passkey",
            "approved_at": "2026-03-31T00:00:00Z",
            "expires_at": "2026-04-01T00:00:00Z",
            "approver_key_ref": "owner-root",
            "principal_approval_signature": "0xapproval"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/passports"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_id": "agp_123",
            "status": "active",
            "principal_approval_status": "consumed",
            "bindings": []
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "passport", "create"])
        .assert()
        .success()
        .stdout(contains("\"passport_id\": \"agp_123\""))
        .stdout(contains("\"passport_token\": \"kite_passport_agp_123__"))
        .stdout(contains("\"local_private_key_saved\": true"))
        .stdout(contains("passports.toml"))
        .stderr(contains(
            "IMPORTANT: Save the Passport Token below immediately!",
        ));

    assert!(
        !tempdir.path().join(".kitepass").join("keys").exists(),
        "passport create should no longer persist PEM key files"
    );

    let registry = load_saved_passports(&tempdir);
    assert_eq!(registry.passports.len(), 1);
    assert_eq!(registry.passports[0].passport_id, "agp_123");
    assert_eq!(registry.passports[0].encrypted_key.cipher, "aes-256-gcm");
    assert_eq!(registry.passports[0].encrypted_key.kdf, "hkdf-sha256");
}

#[tokio::test]
async fn wallet_list_renders_text_table_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/wallets"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [
                {
                    "wallet_id": "wal_123",
                    "principal_account_id": "owner_123",
                    "chain_family": "evm",
                    "status": "active",
                    "key_blob_ref": "vault://wallets/wal_123",
                    "key_version": 1,
                    "created_at": "2026-03-31T00:00:00Z",
                    "updated_at": "2026-03-31T00:00:00Z"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["wallet", "list"])
        .assert()
        .success()
        .stdout(contains("wallet_id"))
        .stdout(contains("wal_123"))
        .stdout(contains("chain_family"));
}

#[tokio::test]
async fn wallet_list_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/wallets"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [
                {
                    "wallet_id": "wal_456",
                    "principal_account_id": "owner_123",
                    "chain_family": "evm",
                    "status": "active",
                    "key_blob_ref": "vault://wallets/wal_456",
                    "key_version": 1,
                    "created_at": "2026-03-31T00:00:00Z",
                    "updated_at": "2026-03-31T00:00:00Z"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "wallet", "list"])
        .assert()
        .success()
        .stdout(contains("\"wallet_id\": \"wal_456\""))
        .stdout(contains("\"chain_family\": \"evm\""));
}

#[tokio::test]
async fn logout_clears_local_owner_session_and_preserves_local_passports() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![encrypted_passport("agp_saved")],
        },
    );

    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/logout"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "logged_out"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "logout"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"logged_out\""))
        .stdout(contains("\"local_credentials_cleared\": true"))
        .stdout(contains("\"remote_logout\": \"completed\""))
        .stdout(contains("\"passport_keys_preserved\": true"));

    let config = load_saved_config(&tempdir);
    assert!(config.access_token.is_none());
    assert!(config.encrypted_access_token.is_none());
    assert!(!tempdir
        .path()
        .join(".kitepass")
        .join("access-token.secret")
        .exists());

    let registry = load_saved_passports(&tempdir);
    assert_eq!(registry.passports.len(), 1);
    assert_eq!(registry.passports[0].passport_id, "agp_saved");
}

#[tokio::test]
async fn login_json_flow_persists_access_token() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/device-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev_123",
            "user_code": "USER-CODE",
            "verification_uri": "https://kitepass.xyz/device",
            "expires_in": 300,
            "interval": 1
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/poll/dev_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token_mock_123",
            "error": null
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "--non-interactive", "--quiet", "login"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"authenticated\""))
        .stdout(contains("\"token_saved\": true"));

    let saved = load_saved_config(&tempdir);
    assert_eq!(saved.access_token.as_deref(), Some("token_mock_123"));
    assert!(saved.encrypted_access_token.is_some());

    let raw_path = newest_existing_path(config_paths(&tempdir)).expect("config should exist");
    let raw_config = fs::read_to_string(raw_path).expect("raw config should be readable");
    assert!(!raw_config.contains("token_mock_123"));
    assert!(raw_config.contains("encrypted_access_token"));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let device_body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("device request body should be json");
    let poll_body: serde_json::Value =
        serde_json::from_slice(&requests[1].body).expect("poll request body should be json");

    assert_eq!(device_body["code_challenge_method"], "S256");
    assert!(device_body["code_challenge"].as_str().is_some());
    assert!(poll_body["code_verifier"].as_str().is_some());
}

#[tokio::test]
async fn policy_activate_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/passport-policies/pol_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "passport_id": "agp_123",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "1000",
            "allowed_destinations": ["0xabc"],
            "valid_from": "2026-03-31T00:00:00Z",
            "valid_until": "2026-04-01T00:00:00Z",
            "state": "active",
            "version": 1
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "passport-policy",
            "activate",
            "--passport-policy-id",
            "pol_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"active\""));
}

#[tokio::test]
async fn audit_verify_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/audit-events/verify"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "event_count": 3,
            "latest_event_id": "evt_123"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "audit", "verify"])
        .assert()
        .success()
        .stdout(contains("\"valid\": true"))
        .stdout(contains("\"latest_event_id\": \"evt_123\""));
}

#[tokio::test]
async fn operations_get_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/operations/op_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operation_id": "op_123",
            "operation_type": "transaction_submission",
            "request_id": "req_123",
            "status": "completed",
            "resource_type": "transaction",
            "resource_id": "0xtx",
            "error_code": null,
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:00:00Z",
            "poll_after_ms": null
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "operations", "get", "--operation-id", "op_123"])
        .assert()
        .success()
        .stdout(contains("\"operation_id\": \"op_123\""))
        .stdout(contains("\"status\": \"completed\""));
}

#[tokio::test]
async fn sign_validate_mode_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);
    let key = AgentKey::generate();
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![encrypted_passport_from_key("agp_123", &key)],
        },
    );
    let passport_token = PassportToken::format("agp_123", TEST_COMBINED_SECRET);

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_123",
            "valid": true,
            "resolved_wallet_id": "wal_123",
            "passport_policy_id": "pol_123",
            "passport_policy_version": 1,
            "normalized": {
                "wallet_id": "wal_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .env("KITE_PASSPORT_TOKEN", &passport_token)
        .args([
            "--json",
            "sign",
            "--validate",
            "--wallet-id",
            "wal_123",
            "--chain-id",
            "eip155:8453",
            "--signing-type",
            "transaction",
            "--payload",
            "0xdeadbeef",
            "--destination",
            "0xabc",
            "--value",
            "10",
        ])
        .assert()
        .success()
        .stdout(contains("\"valid\": true"))
        .stdout(contains("\"resolved_wallet_id\": \"wal_123\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let validate_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sign-intents/validate")
        .expect("validate request should be present");
    let validate_body: serde_json::Value =
        serde_json::from_slice(&validate_req.body).expect("validate body should be json");

    assert_eq!(validate_body["passport_id"], "agp_123");
    assert!(validate_body["agent_proof"]["signature"]
        .as_str()
        .expect("validate proof should be a string")
        .starts_with("0x"));
}

#[test]
fn sign_requires_passport_token() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");

    cli_command(&tempdir)
        .args([
            "sign",
            "--chain-id",
            "eip155:8453",
            "--payload",
            "0xdeadbeef",
        ])
        .assert()
        .failure()
        .stderr(contains("requires KITE_PASSPORT_TOKEN"));
}

#[tokio::test]
async fn audit_list_renders_json_output_for_wallet_filter() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/audit-events"))
        .and(query_param("wallet_id", "wal_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{
                "event_id": "evt_123",
                "action": "authorization_succeeded",
                "trace_id": "trace_123",
                "request_id": "req_123",
                "wallet_id": "wal_123",
                "passport_id": "agp_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "outcome": "success",
                "passport_policy_id": "pol_123",
                "passport_policy_version": 1,
                "permit_id": "permit_123",
                "enclave_receipt": null,
                "previous_event_hash": "root",
                "timestamp": "2026-03-31T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "audit", "list", "--wallet-id", "wal_123"])
        .assert()
        .success()
        .stdout(contains("\"event_id\": \"evt_123\""))
        .stdout(contains("\"wallet_id\": \"wal_123\""));
}

#[tokio::test]
async fn passport_get_renders_json_output_with_bindings_and_usage() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/passports/agp_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_id": "agp_123",
            "principal_account_id": "pac_dev",
            "public_key": "feedface",
            "key_alg": "ed25519",
            "key_address": "ed25519:feedface",
            "status": "active",
            "expires_at": "2026-04-30T00:00:00Z",
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/passports/agp_123/bindings"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bindings": [{
                "binding_id": "bind_123",
                "passport_id": "agp_123",
                "wallet_id": "wal_123",
                "passport_policy_id": "pol_123",
                "passport_policy_version": 1,
                "status": "active",
                "is_default": true,
                "selection_priority": 0
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/passports/agp_123/usage"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "usage": {
                "binding_id": "bind_123",
                "passport_policy_id": "pol_123",
                "passport_policy_version": 1,
                "wallet_id": "wal_123",
                "passport_id": "agp_123",
                "lifetime_spent": "50",
                "daily_window_started_at": "2026-03-31T00:00:00Z",
                "daily_spent": "10",
                "rolling_window_started_at": "2026-03-31T00:00:00Z",
                "rolling_spent": "10",
                "last_consumed_request_id": "req_123",
                "updated_at": "2026-03-31T00:00:00Z"
            }
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "passport", "get", "--passport-id", "agp_123"])
        .assert()
        .success()
        .stdout(contains("\"passport_id\": \"agp_123\""))
        .stdout(contains("\"binding_id\": \"bind_123\""))
        .stdout(contains("\"daily_spent\": \"10\""));
}

#[tokio::test]
async fn passport_freeze_and_revoke_render_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/passports/agp_freeze_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_id": "agp_freeze_123",
            "principal_account_id": "pac_dev",
            "public_key": "feedface",
            "key_alg": "ed25519",
            "key_address": "ed25519:feedface",
            "status": "frozen",
            "expires_at": "2026-04-30T00:00:00Z",
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:10:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/passports/agp_revoke_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_id": "agp_revoke_123",
            "principal_account_id": "pac_dev",
            "public_key": "feedface",
            "key_alg": "ed25519",
            "key_address": "ed25519:feedface",
            "status": "revoked",
            "expires_at": "2026-04-30T00:00:00Z",
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:20:00Z"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "passport",
            "freeze",
            "--passport-id",
            "agp_freeze_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_id\": \"agp_freeze_123\""))
        .stdout(contains("\"status\": \"frozen\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "passport",
            "revoke",
            "--passport-id",
            "agp_revoke_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_id\": \"agp_revoke_123\""))
        .stdout(contains("\"status\": \"revoked\""));
}

#[tokio::test]
async fn policy_create_renders_json_output_and_posts_expected_body() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/passport-policies"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_policy_id": "pol_create_123",
            "binding_id": "",
            "wallet_id": "wal_123",
            "passport_id": "",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "1000",
            "allowed_destinations": ["0xabc"],
            "valid_from": "2026-03-31T00:00:00Z",
            "valid_until": "2026-04-01T00:00:00Z",
            "state": "draft",
            "version": 1
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--allowed-chain",
            "eip155:8453",
            "--allowed-action",
            "transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "1000",
            "--allowed-destination",
            "0xabc",
            "--valid-for-hours",
            "24",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_policy_id\": \"pol_create_123\""))
        .stdout(contains("\"state\": \"draft\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("policy create body should be json");
    assert_eq!(body["wallet_id"], "wal_123");
    assert!(body.get("passport_id").is_none() || body["passport_id"].is_null());
    assert_eq!(body["allowed_chains"][0], "eip155:8453");
    assert_eq!(body["allowed_actions"][0], "transaction");
    assert_eq!(body["allowed_destinations"][0], "0xabc");
}

#[tokio::test]
async fn policy_create_uses_policy_first_payload() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/passport-policies"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_policy_id": "pol_create_456",
            "binding_id": "",
            "wallet_id": "wal_123",
            "passport_id": "",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "1000",
            "allowed_destinations": ["0xabc"],
            "valid_from": "2026-03-31T00:00:00Z",
            "valid_until": "2026-04-01T00:00:00Z",
            "state": "draft",
            "version": 1
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--allowed-chain",
            "eip155:8453",
            "--allowed-action",
            "transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "1000",
            "--allowed-destination",
            "0xabc",
            "--valid-for-hours",
            "24",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_policy_id\": \"pol_create_456\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("policy create body should be json");
    assert_eq!(body["wallet_id"], "wal_123");
    assert!(body.get("passport_id").is_none());
}

#[tokio::test]
async fn policy_get_and_deactivate_render_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/passport-policies/pol_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "passport_id": "agp_123",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "1000",
            "allowed_destinations": ["0xabc"],
            "valid_from": "2026-03-31T00:00:00Z",
            "valid_until": "2026-04-01T00:00:00Z",
            "state": "active",
            "version": 1
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/passport-policies/pol_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passport_policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "passport_id": "agp_123",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "1000",
            "allowed_destinations": ["0xabc"],
            "valid_from": "2026-03-31T00:00:00Z",
            "valid_until": "2026-04-01T00:00:00Z",
            "state": "deactivated",
            "version": 1
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "passport-policy",
            "get",
            "--passport-policy-id",
            "pol_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"active\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "passport-policy",
            "deactivate",
            "--passport-policy-id",
            "pol_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"passport_policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"deactivated\""));
}

#[tokio::test]
async fn audit_get_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("GET"))
        .and(path("/v1/audit-events/evt_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "event_id": "evt_123",
            "action": "authorization_succeeded",
            "trace_id": "trace_123",
            "request_id": "req_123",
            "wallet_id": "wal_123",
            "passport_id": "agp_123",
            "chain_id": "eip155:8453",
            "payload_hash": "0xhash",
            "outcome": "success",
            "passport_policy_id": "pol_123",
            "passport_policy_version": 1,
            "permit_id": "permit_123",
            "enclave_receipt": null,
            "previous_event_hash": "root",
            "timestamp": "2026-03-31T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "audit", "get", "--event-id", "evt_123"])
        .assert()
        .success()
        .stdout(contains("\"event_id\": \"evt_123\""))
        .stdout(contains("\"action\": \"authorization_succeeded\""));
}

#[tokio::test]
async fn wallet_get_freeze_and_revoke_render_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    let wallet_body = serde_json::json!({
        "wallet_id": "wal_123",
        "principal_account_id": "owner_123",
        "chain_family": "evm",
        "status": "active",
        "key_blob_ref": "vault://wallets/wal_123",
        "key_version": 1,
        "created_at": "2026-03-31T00:00:00Z",
        "updated_at": "2026-03-31T00:00:00Z"
    });

    Mock::given(method("GET"))
        .and(path("/v1/wallets/wal_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wallet_body.clone()))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/wallets/wal_freeze_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet_id": "wal_freeze_123",
            "principal_account_id": "owner_123",
            "chain_family": "evm",
            "status": "frozen",
            "key_blob_ref": "vault://wallets/wal_freeze_123",
            "key_version": 1,
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:10:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/wallets/wal_revoke_123"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet_id": "wal_revoke_123",
            "principal_account_id": "owner_123",
            "chain_family": "evm",
            "status": "revoked",
            "key_blob_ref": "vault://wallets/wal_revoke_123",
            "key_version": 1,
            "created_at": "2026-03-31T00:00:00Z",
            "updated_at": "2026-03-31T00:20:00Z"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "wallet", "get", "--wallet-id", "wal_123"])
        .assert()
        .success()
        .stdout(contains("\"wallet_id\": \"wal_123\""))
        .stdout(contains("\"status\": \"active\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "wallet",
            "freeze",
            "--wallet-id",
            "wal_freeze_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"wallet_id\": \"wal_freeze_123\""))
        .stdout(contains("\"status\": \"frozen\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "wallet",
            "revoke",
            "--wallet-id",
            "wal_revoke_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"wallet_id\": \"wal_revoke_123\""))
        .stdout(contains("\"status\": \"revoked\""));
}

#[tokio::test]
async fn wallet_import_reads_secret_from_stdin_and_uploads_ciphertext() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    let vault_keypair = generate_recipient_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import-sessions"))
        .and(header("authorization", "Bearer principal-token"))
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
                "principal_account_id": "pac_dev",
                "principal_session_id": "pss_dev",
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
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operation_id": "op_123",
            "session_id": "sess_999",
            "status": "imported",
            "wallet_id": "wal_123"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "--quiet",
            "wallet",
            "import",
            "--chain-family",
            "base",
            "--name",
            "test-wallet",
        ])
        .write_stdin("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7\n")
        .assert()
        .success()
        .stdout(contains("\"operation_id\": \"op_123\""))
        .stdout(contains("\"wallet_id\": \"wal_123\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let session_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/wallets/import-sessions")
        .expect("import session request should be present");
    let upload_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/wallets/import-sessions/sess_999/upload")
        .expect("upload request should be present");

    let session_body: serde_json::Value =
        serde_json::from_slice(&session_req.body).expect("import session body should be json");
    let upload_body: serde_json::Value =
        serde_json::from_slice(&upload_req.body).expect("upload body should be json");

    assert_eq!(session_body["chain_family"], "evm");
    assert_eq!(session_body["label"], "test-wallet");
    assert_eq!(upload_body["vault_signer_instance_id"], "vs_dev_1");
    assert_eq!(upload_body["aad"]["principal_account_id"], "pac_dev");
    assert_eq!(upload_body["aad"]["principal_session_id"], "pss_dev");
    assert_eq!(upload_body["aad"]["request_id"], "req_dev");
    assert_eq!(upload_body["aad"]["vault_signer_instance_id"], "vs_dev_1");
    assert!(
        upload_body["encapsulated_key"]
            .as_str()
            .expect("encapsulated key should be string")
            .len()
            > 10
    );
    assert!(
        upload_body["ciphertext"]
            .as_str()
            .expect("ciphertext should be string")
            .len()
            > 10
    );
}

#[tokio::test]
async fn sign_broadcast_renders_json_output_and_sends_agent_proof() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    let key = AgentKey::generate();
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![encrypted_passport_from_key("agp_123", &key)],
        },
    );
    let passport_token = PassportToken::format("agp_123", TEST_COMBINED_SECRET);

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_123",
            "valid": true,
            "resolved_wallet_id": "wal_123",
            "passport_policy_id": "pol_123",
            "passport_policy_version": 1,
            "normalized": {
                "wallet_id": "wal_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge_id": "sch_123",
            "passport_id": "agp_123",
            "challenge_nonce": "nonce_challenge_123",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_123",
            "passport_id": "agp_123",
            "session_nonce": "nonce_123",
            "status": "active",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/signatures"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_123",
            "status": "pending",
            "signature": "0xsigned",
            "enclave_receipt": "0xreceipt",
            "operation_id": "op_123",
            "poll_after_ms": 500
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .env("KITE_PASSPORT_TOKEN", &passport_token)
        .args([
            "--json",
            "sign",
            "--passport-id",
            "agp_123",
            "--wallet-id",
            "wal_123",
            "--chain-id",
            "eip155:8453",
            "--signing-type",
            "transaction",
            "--payload",
            "0xdeadbeef",
            "--destination",
            "0xabc",
            "--value",
            "10",
            "--broadcast",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"pending\""))
        .stdout(contains("\"operation_id\": \"op_123\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let validate_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sign-intents/validate")
        .expect("validate request should be present");
    let session_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sessions")
        .expect("session request should be present");
    let challenge_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sessions/challenge")
        .expect("session challenge request should be present");
    let sign_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/signatures")
        .expect("sign request should be present");

    let validate_body: serde_json::Value =
        serde_json::from_slice(&validate_req.body).expect("validate body should be json");
    let challenge_body: serde_json::Value =
        serde_json::from_slice(&challenge_req.body).expect("challenge body should be json");
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_req.body).expect("session body should be json");
    let sign_body: serde_json::Value =
        serde_json::from_slice(&sign_req.body).expect("sign body should be json");

    assert_eq!(validate_body["wallet_id"], "wal_123");
    assert_eq!(challenge_body["passport_id"], "agp_123");
    assert!(validate_body["agent_proof"]["signature"]
        .as_str()
        .expect("validate proof should be a string")
        .starts_with("0x"));
    assert_eq!(session_body["passport_id"], "agp_123");
    assert!(session_body["request_id"].is_string());
    assert_eq!(session_body["challenge_id"], "sch_123");
    assert!(session_body["proof_signature"]
        .as_str()
        .expect("session proof should be a string")
        .starts_with("0x"));
    assert_eq!(sign_body["wallet_id"], "wal_123");
    assert_eq!(sign_body["mode"], "sign_and_submit");
    assert_eq!(sign_body["agent_proof"]["passport_id"], "agp_123");
    assert_eq!(sign_body["agent_proof"]["session_nonce"], "nonce_123");
    assert!(sign_body["agent_proof"]["signature"]
        .as_str()
        .expect("signature should be a string")
        .starts_with("0x"));
    assert_eq!(sign_body["request_id"], validate_body["request_id"]);
}

#[test]
fn passport_local_list_and_delete_manage_local_registry() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![
                encrypted_passport("agp_default"),
                encrypted_passport("agp_bot"),
            ],
        },
    );

    cli_command(&tempdir)
        .args(["--json", "passport", "local", "list"])
        .assert()
        .success()
        .stdout(contains("passports.toml"))
        .stdout(contains("\"passport_id\": \"agp_bot\""))
        .stdout(contains("\"private_key_storage\": \"encrypted_inline\""))
        .stdout(contains("\"encryption_cipher\": \"aes-256-gcm\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "passport",
            "local",
            "delete",
            "--passport-id",
            "agp_bot",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"deleted\""))
        .stdout(contains("\"deleted_passport_id\": \"agp_bot\""));

    let registry = load_saved_passports(&tempdir);
    assert_eq!(registry.passports.len(), 1);
    assert_eq!(registry.passports[0].passport_id, "agp_default");
}

#[tokio::test]
async fn sign_uses_token_bound_local_passport_when_flags_are_omitted() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    let default_key = AgentKey::generate();
    let bot_key = AgentKey::generate();

    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![
                encrypted_passport_from_key("agp_default", &default_key),
                encrypted_passport_from_key("agp_bot", &bot_key),
            ],
        },
    );
    let passport_token = PassportToken::format("agp_bot", TEST_COMBINED_SECRET);

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_profile",
            "valid": true,
            "resolved_wallet_id": "wal_profile",
            "passport_policy_id": "pol_profile",
            "passport_policy_version": 1,
            "normalized": {
                "wallet_id": "wal_profile",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge_id": "sch_profile",
            "passport_id": "agp_bot",
            "challenge_nonce": "nonce_profile_challenge",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_profile",
            "passport_id": "agp_bot",
            "session_nonce": "nonce_profile",
            "status": "active",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/signatures"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_profile",
            "status": "pending",
            "signature": "0xsigned",
            "enclave_receipt": "0xreceipt",
            "operation_id": "op_profile",
            "poll_after_ms": 500
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .env("KITE_PASSPORT_TOKEN", &passport_token)
        .args([
            "--json",
            "sign",
            "--wallet-id",
            "wal_profile",
            "--chain-id",
            "eip155:8453",
            "--signing-type",
            "transaction",
            "--payload",
            "0xdeadbeef",
            "--destination",
            "0xabc",
            "--value",
            "10",
            "--broadcast",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"pending\""))
        .stdout(contains("\"operation_id\": \"op_profile\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let session_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sessions")
        .expect("session request should be present");
    let challenge_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sessions/challenge")
        .expect("session challenge request should be present");
    let sign_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/signatures")
        .expect("sign request should be present");

    let challenge_body: serde_json::Value =
        serde_json::from_slice(&challenge_req.body).expect("challenge body should be json");
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_req.body).expect("session body should be json");
    let sign_body: serde_json::Value =
        serde_json::from_slice(&sign_req.body).expect("sign body should be json");

    assert_eq!(challenge_body["passport_id"], "agp_bot");
    assert_eq!(session_body["passport_id"], "agp_bot");
    assert_eq!(session_body["challenge_id"], "sch_profile");
    assert_eq!(sign_body["passport_id"], "agp_bot");
}

/// Critical test: after owner logout, agent signing with KITE_PASSPORT_TOKEN
/// and locally stored encrypted passport keys must still work end-to-end.
#[tokio::test]
async fn agent_sign_works_after_owner_logout() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    let key = AgentKey::generate();
    write_passports(
        &tempdir,
        &LocalPassportRegistry {
            passports: vec![encrypted_passport_from_key("agp_agent", &key)],
        },
    );

    // 1. Logout the owner session
    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/logout"))
        .and(header("authorization", "Bearer principal-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "logged_out"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "logout"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"logged_out\""))
        .stdout(contains("\"local_credentials_cleared\": true"))
        .stdout(contains("\"passport_keys_preserved\": true"));

    // Verify owner session is gone
    let config = load_saved_config(&tempdir);
    assert!(config.access_token.is_none());

    // Verify passport keys are preserved
    let registry = load_saved_passports(&tempdir);
    assert_eq!(registry.passports.len(), 1);
    assert_eq!(registry.passports[0].passport_id, "agp_agent");

    // 2. Now sign as agent (no owner token, just KITE_PASSPORT_TOKEN)
    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_agent",
            "valid": true,
            "resolved_wallet_id": "wal_agent",
            "passport_policy_id": "pol_agent",
            "passport_policy_version": 1,
            "normalized": {
                "wallet_id": "wal_agent",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "challenge_id": "sch_agent",
            "passport_id": "agp_agent",
            "challenge_nonce": "nonce_agent_challenge",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_agent",
            "passport_id": "agp_agent",
            "session_nonce": "nonce_agent",
            "status": "active",
            "expires_at": "2026-03-31T00:05:00Z"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/signatures"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_agent",
            "status": "succeeded",
            "signature": "0xagentsigned",
            "enclave_receipt": "0xreceipt",
            "operation_id": null,
            "poll_after_ms": null
        })))
        .mount(&mock_server)
        .await;

    let passport_token = PassportToken::format("agp_agent", TEST_COMBINED_SECRET);
    cli_command(&tempdir)
        .env("KITE_PASSPORT_TOKEN", &passport_token)
        .args([
            "--json",
            "sign",
            "--chain-id",
            "eip155:8453",
            "--payload",
            "0xdeadbeef",
            "--destination",
            "0xabc",
            "--value",
            "10",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"succeeded\""))
        .stdout(contains("\"signature\": \"0xagentsigned\""));

    // Verify agent proof was sent (no bearer auth, just agent proof)
    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let sign_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/signatures")
        .expect("sign request should be present");
    let sign_body: serde_json::Value =
        serde_json::from_slice(&sign_req.body).expect("sign body should be json");
    assert_eq!(sign_body["agent_proof"]["passport_id"], "agp_agent");
    assert!(sign_body["agent_proof"]["signature"]
        .as_str()
        .expect("agent proof signature should be string")
        .starts_with("0x"));
}

/// Owner commands should fail with exit code 3 after logout.
#[tokio::test]
async fn owner_commands_fail_after_logout() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/logout"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "logged_out"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "logout"])
        .assert()
        .success();

    // wallet list should now fail
    cli_command(&tempdir)
        .args(["wallet", "list"])
        .assert()
        .failure()
        .code(3)
        .stderr(contains("Please run `kitepass login` first"));

    // passport list should also fail
    cli_command(&tempdir)
        .args(["passport", "list"])
        .assert()
        .failure()
        .code(3)
        .stderr(contains("Please run `kitepass login` first"));

    // But passport local list should still work (no auth required)
    cli_command(&tempdir)
        .args(["--json", "passport", "local", "list"])
        .assert()
        .success()
        .stdout(contains("passports.toml"));
}

/// Logout without a prior session should succeed gracefully.
#[test]
fn logout_without_session_succeeds() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");

    cli_command(&tempdir)
        .args(["--json", "logout"])
        .assert()
        .success()
        .stdout(contains("\"had_local_owner_session\": false"))
        .stdout(contains("\"remote_logout\": \"skipped\""));
}

/// Logout dry-run should not clear anything.
#[tokio::test]
async fn logout_dry_run_does_not_clear_session() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    cli_command(&tempdir)
        .args(["--json", "--dry-run", "logout"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"dry_run\""))
        .stdout(contains("\"had_local_owner_session\": true"))
        .stdout(contains("\"local_credentials_cleared\": false"))
        .stdout(contains("\"remote_logout\": \"would_attempt\""));

    // Token should still be present
    let config = load_saved_config(&tempdir);
    assert_eq!(config.access_token.as_deref(), Some("principal-token"));
}

/// Logout when remote endpoint fails should still clear local session.
#[tokio::test]
async fn logout_clears_locally_even_when_remote_fails() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("principal-token"));

    Mock::given(method("POST"))
        .and(path("/v1/principal-auth/logout"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "internal_server_error"
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "logout"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"logged_out\""))
        .stdout(contains("\"local_credentials_cleared\": true"))
        .stdout(contains("\"remote_logout\": \"failed\""))
        .stdout(contains("\"remote_error\":"));

    let config = load_saved_config(&tempdir);
    assert!(config.access_token.is_none());
}
