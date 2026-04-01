use assert_cmd::Command;
use kitepass_config::{AgentIdentity, AgentRegistry, CliConfig};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::hpke::{IMPORT_ENCRYPTION_SCHEME, generate_recipient_keypair};
use predicates::str::contains;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_paths(tempdir: &TempDir) -> [std::path::PathBuf; 2] {
    [
        tempdir.path().join("kitepass").join("config.toml"),
        tempdir
            .path()
            .join("Library")
            .join("Application Support")
            .join("kitepass")
            .join("config.toml"),
    ]
}

fn agents_paths(tempdir: &TempDir) -> [std::path::PathBuf; 2] {
    [
        tempdir.path().join("kitepass").join("agents.toml"),
        tempdir
            .path()
            .join("Library")
            .join("Application Support")
            .join("kitepass")
            .join("agents.toml"),
    ]
}

fn write_config(tempdir: &TempDir, api_url: Option<&str>, access_token: Option<&str>) {
    let config = CliConfig {
        api_url: api_url.map(str::to_string),
        default_chain: None,
        access_token: access_token.map(str::to_string),
    };

    for path in config_paths(tempdir) {
        config.save(&path).expect("config should save");
    }
}

fn load_saved_config(tempdir: &TempDir) -> CliConfig {
    let mut first = None;
    for path in config_paths(tempdir) {
        if path.exists() {
            let config = CliConfig::load(&path).expect("config should load");
            if config.access_token.is_some() {
                return config;
            }
            first = Some(config);
        }
    }

    first.expect("expected CLI config to exist")
}

fn load_saved_agents(tempdir: &TempDir) -> AgentRegistry {
    let mut first = None;
    for path in agents_paths(tempdir) {
        if path.exists() {
            let registry = AgentRegistry::load(&path).expect("agent registry should load");
            if !registry.agents.is_empty() {
                return registry;
            }
            first = Some(registry);
        }
    }
    first.unwrap_or_default()
}

fn write_agents(tempdir: &TempDir, registry: &AgentRegistry) {
    for path in agents_paths(tempdir) {
        registry.save(&path).expect("agent registry should save");
    }
}

fn cli_command(tempdir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("kitepass").expect("binary should build");
    command
        .env("XDG_CONFIG_HOME", tempdir.path())
        .env("HOME", tempdir.path());
    command
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
fn access_key_create_dry_run_emits_json_without_writing_keys() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    write_config(
        &tempdir,
        Some("https://api.example.invalid"),
        Some("owner-token"),
    );

    cli_command(&tempdir)
        .args([
            "--json",
            "--dry-run",
            "access-key",
            "create",
            "--name",
            "worker-key",
        ])
        .assert()
        .success()
        .stdout(contains("\"dry_run\": true"))
        .stdout(contains("\"action\": \"access_key.create\""))
        .stdout(contains("\"profile_name\": \"worker-key\""));

    assert!(
        !tempdir.path().join("kitepass").join("keys").exists(),
        "dry-run should not materialize key files"
    );
}

#[tokio::test]
async fn access_key_create_emits_clean_json_and_writes_key_file() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("POST"))
        .and(path("/v1/agent-access-keys:prepare"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "intent_id": "intent_123",
            "intent_hash": "hash_123",
            "approval_url": "https://kitepass.xyz/approve/intent_123",
            "approval_status": "pending_owner_step_up",
            "approval_expires_at": "2026-04-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/provisioning-intents/intent_123/approve"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "owner_approval_id": "oa_123",
            "record_type": "owner_approval_record",
            "record_version": 1,
            "owner_id": "own_dev",
            "intent_id": "intent_123",
            "intent_hash": "hash_123",
            "operation": "create_agent_access_key",
            "approval_method": "passkey",
            "approved_at": "2026-03-31T00:00:00Z",
            "expires_at": "2026-04-01T00:00:00Z",
            "approver_key_ref": "owner-root",
            "owner_approval_signature": "0xapproval"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/agent-access-keys"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_key_id": "aak_123",
            "status": "active",
            "owner_approval_status": "consumed",
            "bindings": []
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args(["--json", "access-key", "create", "--name", "worker-key"])
        .assert()
        .success()
        .stdout(contains("\"access_key_id\": \"aak_123\""))
        .stdout(contains("\"private_key_path\":"));

    assert!(
        tempdir
            .path()
            .join("Library")
            .join("Application Support")
            .join("kitepass")
            .join("keys")
            .exists()
            || tempdir.path().join("kitepass").join("keys").exists(),
        "access-key create should persist the generated private key"
    );

    let registry = load_saved_agents(&tempdir);
    assert_eq!(registry.active_profile.as_deref(), Some("worker-key"));
    assert_eq!(registry.agents.len(), 1);
    assert_eq!(registry.agents[0].name, "worker-key");
    assert_eq!(registry.agents[0].access_key_id, "aak_123");
}

#[tokio::test]
async fn wallet_list_renders_text_table_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/wallets"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [
                {
                    "wallet_id": "wal_123",
                    "owner_id": "owner_123",
                    "chain_family": "eip155",
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
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/wallets"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [
                {
                    "wallet_id": "wal_456",
                    "owner_id": "owner_123",
                    "chain_family": "eip155",
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
        .stdout(contains("\"chain_family\": \"eip155\""));
}

#[tokio::test]
async fn login_json_flow_persists_access_token() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    Mock::given(method("POST"))
        .and(path("/v1/owner-auth/device-code"))
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
        .and(path("/v1/owner-auth/poll/dev_123"))
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
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("POST"))
        .and(path("/v1/policies/pol_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
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
        .args(["--json", "policy", "activate", "--policy-id", "pol_123"])
        .assert()
        .success()
        .stdout(contains("\"policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"active\""));
}

#[tokio::test]
async fn audit_verify_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("POST"))
        .and(path("/v1/audit-events/verify"))
        .and(header("authorization", "Bearer owner-token"))
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
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/operations/op_123"))
        .and(header("authorization", "Bearer owner-token"))
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
async fn sign_validate_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

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
                "payload_hash": "0xhash",
                "destination": "0xabc",
                "value": "10"
            }
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "sign",
            "validate",
            "--access-key-id",
            "aak_123",
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
}

#[tokio::test]
async fn audit_list_renders_json_output_for_wallet_filter() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/audit-events"))
        .and(query_param("wallet_id", "wal_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{
                "event_id": "evt_123",
                "action": "authorization_succeeded",
                "trace_id": "trace_123",
                "request_id": "req_123",
                "wallet_id": "wal_123",
                "access_key_id": "aak_123",
                "chain_id": "eip155:8453",
                "payload_hash": "0xhash",
                "outcome": "success",
                "policy_id": "pol_123",
                "policy_version": 1,
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
async fn access_key_get_renders_json_output_with_bindings_and_usage() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/agent-access-keys/aak_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_key_id": "aak_123",
            "owner_id": "own_dev",
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
        .and(path("/v1/agent-access-keys/aak_123/bindings"))
        .and(header("authorization", "Bearer owner-token"))
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
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "usage": {
                "binding_id": "bind_123",
                "policy_id": "pol_123",
                "policy_version": 1,
                "wallet_id": "wal_123",
                "access_key_id": "aak_123",
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
        .args(["--json", "access-key", "get", "--key-id", "aak_123"])
        .assert()
        .success()
        .stdout(contains("\"access_key_id\": \"aak_123\""))
        .stdout(contains("\"binding_id\": \"bind_123\""))
        .stdout(contains("\"daily_spent\": \"10\""));
}

#[tokio::test]
async fn access_key_freeze_and_revoke_render_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("POST"))
        .and(path("/v1/agent-access-keys/aak_freeze_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_key_id": "aak_freeze_123",
            "owner_id": "own_dev",
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
        .and(path("/v1/agent-access-keys/aak_revoke_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_key_id": "aak_revoke_123",
            "owner_id": "own_dev",
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
            "access-key",
            "freeze",
            "--key-id",
            "aak_freeze_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"access_key_id\": \"aak_freeze_123\""))
        .stdout(contains("\"status\": \"frozen\""));

    cli_command(&tempdir)
        .args([
            "--json",
            "access-key",
            "revoke",
            "--key-id",
            "aak_revoke_123",
        ])
        .assert()
        .success()
        .stdout(contains("\"access_key_id\": \"aak_revoke_123\""))
        .stdout(contains("\"status\": \"revoked\""));
}

#[tokio::test]
async fn policy_create_renders_json_output_and_posts_expected_body() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("POST"))
        .and(path("/v1/policies"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy_id": "pol_create_123",
            "binding_id": "bind_create_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
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
            "policy",
            "create",
            "--name",
            "daily-policy",
            "--wallet-id",
            "wal_123",
            "--access-key-id",
            "aak_123",
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
        .stdout(contains("\"policy_id\": \"pol_create_123\""))
        .stdout(contains("\"state\": \"draft\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("policy create body should be json");
    assert_eq!(body["wallet_id"], "wal_123");
    assert_eq!(body["access_key_id"], "aak_123");
    assert_eq!(body["allowed_chains"][0], "eip155:8453");
    assert_eq!(body["allowed_actions"][0], "transaction");
    assert_eq!(body["allowed_destinations"][0], "0xabc");
}

#[tokio::test]
async fn policy_get_and_deactivate_render_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/policies/pol_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
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
        .and(path("/v1/policies/pol_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy_id": "pol_123",
            "binding_id": "bind_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
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
        .args(["--json", "policy", "get", "--policy-id", "pol_123"])
        .assert()
        .success()
        .stdout(contains("\"policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"active\""));

    cli_command(&tempdir)
        .args(["--json", "policy", "deactivate", "--policy-id", "pol_123"])
        .assert()
        .success()
        .stdout(contains("\"policy_id\": \"pol_123\""))
        .stdout(contains("\"state\": \"deactivated\""));
}

#[tokio::test]
async fn audit_get_renders_json_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    Mock::given(method("GET"))
        .and(path("/v1/audit-events/evt_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "event_id": "evt_123",
            "action": "authorization_succeeded",
            "trace_id": "trace_123",
            "request_id": "req_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
            "chain_id": "eip155:8453",
            "payload_hash": "0xhash",
            "outcome": "success",
            "policy_id": "pol_123",
            "policy_version": 1,
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
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    let wallet_body = serde_json::json!({
        "wallet_id": "wal_123",
        "owner_id": "owner_123",
        "chain_family": "eip155",
        "status": "active",
        "key_blob_ref": "vault://wallets/wal_123",
        "key_version": 1,
        "created_at": "2026-03-31T00:00:00Z",
        "updated_at": "2026-03-31T00:00:00Z"
    });

    Mock::given(method("GET"))
        .and(path("/v1/wallets/wal_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wallet_body.clone()))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/wallets/wal_freeze_123"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet_id": "wal_freeze_123",
            "owner_id": "owner_123",
            "chain_family": "eip155",
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
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallet_id": "wal_revoke_123",
            "owner_id": "owner_123",
            "chain_family": "eip155",
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
    write_config(&tempdir, Some(&mock_server.uri()), Some("owner-token"));

    let vault_keypair = generate_recipient_keypair();

    Mock::given(method("POST"))
        .and(path("/v1/wallets/import-sessions"))
        .and(header("authorization", "Bearer owner-token"))
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
        .and(header("authorization", "Bearer owner-token"))
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
            "--chain",
            "base",
            "--name",
            "test-wallet",
        ])
        .write_stdin("my_secret_mnemonic\n")
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

    assert_eq!(session_body["chain_family"], "base");
    assert_eq!(session_body["label"], "test-wallet");
    assert_eq!(upload_body["vault_signer_instance_id"], "vs_dev_1");
    assert_eq!(upload_body["aad"]["owner_id"], "own_dev");
    assert_eq!(upload_body["aad"]["owner_session_id"], "oas_dev");
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
async fn sign_submit_renders_json_output_and_sends_agent_proof() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    let key = AgentKey::generate();
    let pem = key.export_pem().expect("key should export");
    let key_path = tempdir.path().join("agent.pem");
    fs::write(&key_path, pem).expect("key should write");

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_123",
            "valid": true,
            "resolved_wallet_id": "wal_123",
            "policy_id": "pol_123",
            "policy_version": 1,
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
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_123",
            "access_key_id": "aak_123",
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
            "status": "submitted",
            "signature": "0xsigned",
            "enclave_receipt": "0xreceipt",
            "operation_id": "op_123",
            "poll_after_ms": 500
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .args([
            "--json",
            "sign",
            "submit",
            "--access-key-id",
            "aak_123",
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
            "--key-path",
            key_path.to_str().expect("key path should be utf-8"),
            "--sign-and-submit",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"submitted\""))
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
    let sign_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/signatures")
        .expect("sign request should be present");

    let validate_body: serde_json::Value =
        serde_json::from_slice(&validate_req.body).expect("validate body should be json");
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_req.body).expect("session body should be json");
    let sign_body: serde_json::Value =
        serde_json::from_slice(&sign_req.body).expect("sign body should be json");

    assert_eq!(validate_body["wallet_id"], "wal_123");
    assert_eq!(session_body["access_key_id"], "aak_123");
    assert_eq!(sign_body["wallet_id"], "wal_123");
    assert_eq!(sign_body["mode"], "sign_and_submit");
    assert_eq!(sign_body["agent_proof"]["access_key_id"], "aak_123");
    assert_eq!(sign_body["agent_proof"]["session_nonce"], "nonce_123");
    assert!(
        sign_body["agent_proof"]["signature"]
            .as_str()
            .expect("signature should be a string")
            .starts_with("0x")
    );
    assert_eq!(sign_body["request_id"], validate_body["request_id"]);
}

#[test]
fn profile_list_use_and_delete_manage_local_registry() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    write_agents(
        &tempdir,
        &AgentRegistry {
            active_profile: Some("default".to_string()),
            agents: vec![
                AgentIdentity {
                    name: "default".to_string(),
                    access_key_id: "aak_default".to_string(),
                    private_key_path: "/tmp/default.pem".to_string(),
                    public_key_hex: "abc".to_string(),
                },
                AgentIdentity {
                    name: "trading_bot".to_string(),
                    access_key_id: "aak_bot".to_string(),
                    private_key_path: "/tmp/bot.pem".to_string(),
                    public_key_hex: "def".to_string(),
                },
            ],
        },
    );

    cli_command(&tempdir)
        .args(["--json", "profile", "list"])
        .assert()
        .success()
        .stdout(contains("\"active_profile\": \"default\""))
        .stdout(contains("\"name\": \"trading_bot\""));

    cli_command(&tempdir)
        .args(["--json", "profile", "use", "--name", "trading_bot"])
        .assert()
        .success()
        .stdout(contains("\"active_profile\": \"trading_bot\""));

    let registry = load_saved_agents(&tempdir);
    assert_eq!(registry.active_profile.as_deref(), Some("trading_bot"));

    cli_command(&tempdir)
        .args(["--json", "profile", "delete", "--name", "trading_bot"])
        .assert()
        .success()
        .stdout(contains("\"status\": \"deleted\""));

    let registry = load_saved_agents(&tempdir);
    assert_eq!(registry.active_profile.as_deref(), Some("default"));
    assert_eq!(registry.agents.len(), 1);
    assert_eq!(registry.agents[0].name, "default");
}

#[tokio::test]
async fn sign_submit_uses_selected_profile_when_flags_are_omitted() {
    let tempdir = tempfile::tempdir().expect("tempdir should exist");
    let mock_server = MockServer::start().await;
    write_config(&tempdir, Some(&mock_server.uri()), None);

    let default_key = AgentKey::generate();
    let default_path = tempdir.path().join("default.pem");
    fs::write(
        &default_path,
        default_key.export_pem().expect("default key should export"),
    )
    .expect("default key should write");

    let bot_key = AgentKey::generate();
    let bot_path = tempdir.path().join("trading_bot.pem");
    fs::write(&bot_path, bot_key.export_pem().expect("bot key should export"))
        .expect("bot key should write");

    write_agents(
        &tempdir,
        &AgentRegistry {
            active_profile: Some("default".to_string()),
            agents: vec![
                AgentIdentity {
                    name: "default".to_string(),
                    access_key_id: "aak_default".to_string(),
                    private_key_path: default_path.to_string_lossy().to_string(),
                    public_key_hex: default_key.public_key_hex(),
                },
                AgentIdentity {
                    name: "trading_bot".to_string(),
                    access_key_id: "aak_bot".to_string(),
                    private_key_path: bot_path.to_string_lossy().to_string(),
                    public_key_hex: bot_key.public_key_hex(),
                },
            ],
        },
    );

    Mock::given(method("POST"))
        .and(path("/v1/sign-intents/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "req_mock_profile",
            "valid": true,
            "resolved_wallet_id": "wal_profile",
            "policy_id": "pol_profile",
            "policy_version": 1,
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
        .and(path("/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "session_id": "sess_profile",
            "access_key_id": "aak_bot",
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
            "status": "submitted",
            "signature": "0xsigned",
            "enclave_receipt": "0xreceipt",
            "operation_id": "op_profile",
            "poll_after_ms": 500
        })))
        .mount(&mock_server)
        .await;

    cli_command(&tempdir)
        .env("KITE_PROFILE", "trading_bot")
        .args([
            "--json",
            "sign",
            "submit",
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
            "--sign-and-submit",
        ])
        .assert()
        .success()
        .stdout(contains("\"status\": \"submitted\""))
        .stdout(contains("\"operation_id\": \"op_profile\""));

    let requests = mock_server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let session_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/sessions")
        .expect("session request should be present");
    let sign_req = requests
        .iter()
        .find(|request| request.url.path() == "/v1/signatures")
        .expect("sign request should be present");

    let session_body: serde_json::Value =
        serde_json::from_slice(&session_req.body).expect("session body should be json");
    let sign_body: serde_json::Value =
        serde_json::from_slice(&sign_req.body).expect("sign body should be json");

    assert_eq!(session_body["access_key_id"], "aak_bot");
    assert_eq!(sign_body["access_key_id"], "aak_bot");
}
