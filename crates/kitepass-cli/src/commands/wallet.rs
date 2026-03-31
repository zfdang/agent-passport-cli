use crate::{cli::WalletAction, error::CliError, runtime::Runtime};
use anyhow::{Context, Result};
use kitepass_api_client::{
    ImportAad, ImportAttestationResponse, ImportSessionResponse, PassportClient,
    UploadWalletCiphertextRequest,
};
use kitepass_config::CliConfig;
use kitepass_crypto::hpke::{IMPORT_ENCRYPTION_SCHEME, seal_to_hex};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct AttestationBundleDocument {
    instance_id: String,
    pcr0: String,
    pcr1: String,
    pcr2: String,
    endpoint_binding: String,
    user_data: AttestationUserData,
}

#[derive(Debug, Deserialize)]
struct AttestationUserData {
    document_version: u32,
    import_session_id: String,
    public_api_scope: String,
    authorization_model: String,
    import_encryption_scheme: String,
    measurement_profile_id: String,
    measurement_profile_version: u32,
    reviewed_build_id: String,
    reviewed_build_digest: String,
    build_source: String,
    security_model_ref: String,
}

#[derive(Debug, Serialize)]
struct ImportHpkeInfo<'a> {
    document_version: u32,
    import_session_id: &'a str,
    vault_signer_instance_id: &'a str,
    endpoint_binding: &'a str,
    public_api_scope: &'a str,
    authorization_model: &'a str,
    import_encryption_scheme: &'a str,
    measurement_profile_id: &'a str,
    measurement_profile_version: u32,
    reviewed_build_id: &'a str,
    reviewed_build_digest: &'a str,
    build_source: &'a str,
    security_model_ref: &'a str,
}

fn import_hpke_info(
    session: &ImportSessionResponse,
    attestation: &ImportAttestationResponse,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&ImportHpkeInfo {
        document_version: 1,
        import_session_id: &session.session_id,
        vault_signer_instance_id: &session.vault_signer_instance_id,
        endpoint_binding: &attestation.endpoint_binding,
        public_api_scope: "wallet_import_attestation",
        authorization_model: &session.vault_signer_identity.authorization_model,
        import_encryption_scheme: &session.import_encryption_scheme,
        measurement_profile_id: &session.vault_signer_identity.measurement_profile.profile_id,
        measurement_profile_version: session.vault_signer_identity.measurement_profile.version,
        reviewed_build_id: &session.vault_signer_identity.reviewed_build.build_id,
        reviewed_build_digest: &session.vault_signer_identity.reviewed_build.build_digest,
        build_source: &session.vault_signer_identity.reviewed_build.build_source,
        security_model_ref: &session
            .vault_signer_identity
            .reviewed_build
            .security_model_ref,
    })
    .context("Failed to serialize HPKE import info")?)
}

fn verify_import_attestation(
    session: &ImportSessionResponse,
    attestation: &ImportAttestationResponse,
) -> Result<()> {
    if attestation.session_id != session.session_id {
        anyhow::bail!(
            "Vault Signer attestation session did not match the requested import session"
        );
    }

    if attestation.vault_signer_instance_id != session.vault_signer_instance_id {
        anyhow::bail!("Vault Signer attestation instance did not match the import session");
    }

    if session.import_encryption_scheme != IMPORT_ENCRYPTION_SCHEME
        || attestation.import_encryption_scheme != IMPORT_ENCRYPTION_SCHEME
    {
        anyhow::bail!("Vault Signer import encryption scheme did not match HPKE v1");
    }

    if session.vault_signer_identity.instance_id != session.vault_signer_instance_id {
        anyhow::bail!("Gateway returned inconsistent Vault Signer identity metadata");
    }

    let bundle: AttestationBundleDocument =
        serde_json::from_str(&attestation.attestation_bundle)
            .context("Vault Signer attestation bundle was not valid JSON")?;

    if bundle.instance_id != session.vault_signer_identity.instance_id {
        anyhow::bail!("Vault Signer attestation instance did not match Gateway identity metadata");
    }

    if bundle.endpoint_binding != attestation.endpoint_binding {
        anyhow::bail!(
            "Vault Signer attestation endpoint binding did not match the discovery response"
        );
    }

    if bundle.user_data.document_version != 1 {
        anyhow::bail!("Vault Signer attestation user_data version was not supported");
    }

    if bundle.user_data.import_session_id != session.session_id {
        anyhow::bail!("Vault Signer attestation user_data did not match the import session");
    }

    if bundle.user_data.public_api_scope != "wallet_import_attestation" {
        anyhow::bail!("Vault Signer attestation scope did not match wallet import discovery");
    }

    if bundle.user_data.authorization_model != session.vault_signer_identity.authorization_model {
        anyhow::bail!(
            "Vault Signer attestation authorization model did not match Gateway metadata"
        );
    }

    if bundle.user_data.import_encryption_scheme != session.import_encryption_scheme {
        anyhow::bail!("Vault Signer attestation import encryption scheme did not match");
    }

    if bundle.user_data.measurement_profile_id
        != session.vault_signer_identity.measurement_profile.profile_id
        || bundle.user_data.measurement_profile_version
            != session.vault_signer_identity.measurement_profile.version
    {
        anyhow::bail!(
            "Vault Signer attestation measurement profile did not match Gateway metadata"
        );
    }

    if bundle.user_data.reviewed_build_id != session.vault_signer_identity.reviewed_build.build_id
        || bundle.user_data.reviewed_build_digest
            != session.vault_signer_identity.reviewed_build.build_digest
        || bundle.user_data.build_source
            != session.vault_signer_identity.reviewed_build.build_source
        || bundle.user_data.security_model_ref
            != session
                .vault_signer_identity
                .reviewed_build
                .security_model_ref
    {
        anyhow::bail!(
            "Vault Signer attestation reviewed build metadata did not match Gateway metadata"
        );
    }

    let expected = &session.vault_signer_identity.expected_measurements;
    if bundle.pcr0 != expected.pcr0 || bundle.pcr1 != expected.pcr1 || bundle.pcr2 != expected.pcr2
    {
        anyhow::bail!("Vault Signer attestation measurements did not match Gateway expectations");
    }

    Ok(())
}

pub async fn run(action: WalletAction, runtime: &Runtime) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .ok_or(CliError::AuthenticationRequired)?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        WalletAction::List => {
            let wallets = client
                .list_wallets()
                .await
                .context("Failed to list wallets")?;
            runtime.print_data(&wallets)?;
        }
        WalletAction::Import { chain, name } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.import",
                    "chain_family": chain,
                    "label": name,
                }))?;
                return Ok(());
            }

            runtime.progress(format!("Starting hybrid wallet import for chain: {chain}"));

            // 1. Fetch import session
            let session_res = client
                .create_import_session(&chain, name, format!("idem_{}", Uuid::new_v4().simple()))
                .await
                .context("Failed to create import session")?;

            runtime.progress(format!("Session created: {}", session_res.session_id));
            runtime.progress(format!(
                "Target Vault Signer: {}",
                session_res.vault_signer_attestation_endpoint
            ));

            let attestation = client
                .fetch_import_attestation(&session_res.vault_signer_attestation_endpoint)
                .await
                .context("Failed to fetch Vault Signer attestation")?;
            verify_import_attestation(&session_res, &attestation)
                .context("Failed to verify Vault Signer attestation")?;
            runtime.progress(format!(
                "Fetched attestation bundle for session {}",
                attestation.session_id
            ));

            // 2. Prompt for wallet secret
            let wallet_secret = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                runtime.require_secret_from_stdin("wallet import")?;
                dialoguer::Password::new()
                    .with_prompt("Enter Wallet Mnemonic or Hex Private Key")
                    .interact()
                    .context("Failed to read wallet secret")?
            } else {
                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .context("Failed to read wallet secret from stdin")?;
                input.trim().to_string()
            };

            let aad = ImportAad {
                owner_id: session_res.channel_binding.owner_id.clone(),
                owner_session_id: session_res.channel_binding.owner_session_id.clone(),
                request_id: session_res.channel_binding.request_id.clone(),
                vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
            };
            let hpke_info = import_hpke_info(&session_res, &attestation)?;
            let aad_bytes =
                serde_json::to_vec(&aad).context("Failed to serialize import channel binding")?;

            // 3. Encrypt Envelope
            let sealed = seal_to_hex(
                &attestation.import_public_key,
                &hpke_info,
                &aad_bytes,
                wallet_secret.as_bytes(),
            )
            .context("Failed to HPKE-encrypt wallet secret")?;

            // Clear the password string
            let mut wallet_secret = wallet_secret;
            wallet_secret.clear();

            // 4. Upload Ciphertext
            runtime.progress("Uploading encrypted envelope to Passport Gateway...");
            let upload_res = client
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
                .context("Failed to upload wallet ciphertext")?;

            runtime.print_data(&upload_res)?;
        }
        WalletAction::Get { wallet_id } => {
            let wallet = client
                .get_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to get wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
        WalletAction::Freeze { wallet_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.freeze",
                    "wallet_id": wallet_id,
                }))?;
                return Ok(());
            }
            let wallet = client
                .freeze_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to freeze wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
        WalletAction::Revoke { wallet_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.revoke",
                    "wallet_id": wallet_id,
                }))?;
                return Ok(());
            }
            let wallet = client
                .revoke_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to revoke wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_import_attestation;
    use chrono::{Duration, Utc};
    use kitepass_api_client::{
        ChannelBinding, ExpectedMeasurements, ImportAttestationResponse, ImportSessionResponse,
        MeasurementProfile, ReviewedBuild, VaultSignerIdentity,
    };
    use kitepass_crypto::hpke::IMPORT_ENCRYPTION_SCHEME;

    fn sample_session() -> ImportSessionResponse {
        ImportSessionResponse {
            session_id: "wis_123".to_string(),
            status: "awaiting_upload".to_string(),
            vault_signer_instance_id: "vs_dev_1".to_string(),
            vault_signer_attestation_endpoint: "https://api.kitepass.xyz/attest/import/wis_123"
                .to_string(),
            import_encryption_scheme: IMPORT_ENCRYPTION_SCHEME.to_string(),
            vault_signer_identity: VaultSignerIdentity {
                instance_id: "vs_dev_1".to_string(),
                tee_type: "aws_nitro_enclaves_dev".to_string(),
                expected_measurements: ExpectedMeasurements {
                    pcr0: "dev-pcr0".to_string(),
                    pcr1: "dev-pcr1".to_string(),
                    pcr2: "dev-pcr2".to_string(),
                },
                measurement_profile: MeasurementProfile {
                    profile_id: "aws-nitro-dev-v1".to_string(),
                    version: 1,
                },
                reviewed_build: ReviewedBuild {
                    build_id: "vault-signer-dev-reviewed-build-v1".to_string(),
                    build_digest: "sha256:dev-reviewed-build-v1".to_string(),
                    build_source: "apps/vault-signer".to_string(),
                    security_model_ref: "docs/public-security-model.md#attestation-auditability"
                        .to_string(),
                },
                authorization_model: "dual_sign_authorization_tee_signer".to_string(),
            },
            channel_binding: ChannelBinding {
                owner_id: "own_dev".to_string(),
                owner_session_id: "oas_dev".to_string(),
                request_id: "req_123".to_string(),
            },
            expires_at: Utc::now() + Duration::minutes(10),
        }
    }

    fn sample_attestation() -> ImportAttestationResponse {
        ImportAttestationResponse {
            session_id: "wis_123".to_string(),
            vault_signer_instance_id: "vs_dev_1".to_string(),
            import_encryption_scheme: IMPORT_ENCRYPTION_SCHEME.to_string(),
            attestation_bundle: serde_json::json!({
                "instance_id": "vs_dev_1",
                "pcr0": "dev-pcr0",
                "pcr1": "dev-pcr1",
                "pcr2": "dev-pcr2",
                "endpoint_binding": "binding_123",
                "user_data": {
                    "document_version": 1,
                    "import_session_id": "wis_123",
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
            })
            .to_string(),
            import_public_key: "00".repeat(32),
            endpoint_binding: "binding_123".to_string(),
        }
    }

    #[test]
    fn import_attestation_accepts_matching_gateway_identity() {
        verify_import_attestation(&sample_session(), &sample_attestation())
            .expect("matching attestation should be accepted");
    }

    #[test]
    fn import_attestation_rejects_measurement_mismatch() {
        let session = sample_session();
        let mut attestation = sample_attestation();
        attestation.attestation_bundle = serde_json::json!({
            "instance_id": "vs_dev_1",
            "pcr0": "bad-pcr0",
            "pcr1": "dev-pcr1",
            "pcr2": "dev-pcr2",
            "endpoint_binding": "binding_123",
            "user_data": {
                "document_version": 1,
                "import_session_id": "wis_123",
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
        })
        .to_string();

        let err = verify_import_attestation(&session, &attestation)
            .expect_err("mismatched measurements should be rejected");
        assert!(
            err.to_string()
                .contains("measurements did not match Gateway expectations")
        );
    }

    #[test]
    fn import_attestation_rejects_reviewed_build_mismatch() {
        let session = sample_session();
        let mut attestation = sample_attestation();
        attestation.attestation_bundle = serde_json::json!({
            "instance_id": "vs_dev_1",
            "pcr0": "dev-pcr0",
            "pcr1": "dev-pcr1",
            "pcr2": "dev-pcr2",
            "endpoint_binding": "binding_123",
            "user_data": {
                "document_version": 1,
                "import_session_id": "wis_123",
                "public_api_scope": "wallet_import_attestation",
                "authorization_model": "dual_sign_authorization_tee_signer",
                "import_encryption_scheme": IMPORT_ENCRYPTION_SCHEME,
                "measurement_profile_id": "aws-nitro-dev-v1",
                "measurement_profile_version": 1,
                "reviewed_build_id": "vault-signer-dev-reviewed-build-v2",
                "reviewed_build_digest": "sha256:dev-reviewed-build-v1",
                "build_source": "apps/vault-signer",
                "security_model_ref": "docs/public-security-model.md#attestation-auditability"
            }
        })
        .to_string();

        let err = verify_import_attestation(&session, &attestation)
            .expect_err("mismatched reviewed build should be rejected");
        assert!(
            err.to_string()
                .contains("reviewed build metadata did not match Gateway metadata")
        );
    }
}
