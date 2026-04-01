use crate::{cli::ProfileAction, runtime::Runtime};
use anyhow::Result;
use kitepass_config::{AgentRegistry, ConfigError};
use serde_json::json;

pub async fn run(action: ProfileAction, runtime: &Runtime) -> Result<()> {
    let mut registry = AgentRegistry::load_default().unwrap_or_default();

    match action {
        ProfileAction::List => {
            let selected_profile = registry.selected_profile_name();
            runtime.print_data(&json!({
                "active_profile": registry.active_profile,
                "selected_profile": selected_profile,
                "agents": registry.agents,
            }))?;
        }
        ProfileAction::Use { name } => {
            registry
                .set_active_profile(&name)
                .map_err(map_config_error)?;
            registry
                .save_default()
                .map_err(map_config_error)?;
            runtime.print_data(&json!({
                "active_profile": name,
                "status": "updated",
            }))?;
        }
        ProfileAction::Delete { name } => {
            let removed = registry
                .remove_profile(&name)
                .map_err(map_config_error)?;
            registry
                .save_default()
                .map_err(map_config_error)?;
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
