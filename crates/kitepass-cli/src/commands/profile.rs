use crate::{cli::ProfileAction, commands::load_agent_registry, runtime::Runtime};
use anyhow::{Context, Result};
use kitepass_config::ConfigError;
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct AgentProfileSummary<'a> {
    name: &'a str,
    access_key_id: &'a str,
    public_key_hex: &'a str,
    private_key_storage: &'static str,
    encryption_cipher: &'a str,
    encryption_kdf: &'a str,
    active: bool,
    selected: bool,
}

pub async fn run(action: ProfileAction, runtime: &Runtime) -> Result<()> {
    let mut registry = load_agent_registry().context("Failed to load local agent registry")?;

    match action {
        ProfileAction::List => {
            let selected_profile = registry.selected_profile_name();
            let profiles = registry
                .agents
                .iter()
                .map(|agent| AgentProfileSummary {
                    name: &agent.name,
                    access_key_id: &agent.access_key_id,
                    public_key_hex: &agent.public_key_hex,
                    private_key_storage: "encrypted_inline",
                    encryption_cipher: &agent.encrypted_key.cipher,
                    encryption_kdf: &agent.encrypted_key.kdf,
                    active: registry.active_profile.as_deref() == Some(agent.name.as_str()),
                    selected: selected_profile == agent.name,
                })
                .collect::<Vec<_>>();
            runtime.print_data(&json!({
                "active_profile": registry.active_profile,
                "selected_profile": selected_profile,
                "agents": profiles,
            }))?;
        }
        ProfileAction::Use { name } => {
            registry
                .set_active_profile(&name)
                .map_err(map_config_error)?;
            registry.save_default().map_err(map_config_error)?;
            runtime.print_data(&json!({
                "active_profile": name,
                "status": "updated",
            }))?;
        }
        ProfileAction::Delete { name } => {
            let removed = registry.remove_profile(&name).map_err(map_config_error)?;
            registry.save_default().map_err(map_config_error)?;
            runtime.print_data(&json!({
                "status": "deleted",
                "deleted_profile": removed.name,
                "active_profile": registry.active_profile,
            }))?;
        }
    }

    Ok(())
}

fn map_config_error(error: ConfigError) -> anyhow::Error {
    error.into()
}
