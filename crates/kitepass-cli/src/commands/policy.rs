use crate::cli::PolicyAction;
use anyhow::Result;

pub async fn run(action: PolicyAction) -> Result<()> {
    match action {
        PolicyAction::List => {
            println!("kitepass policy list (not yet implemented)");
        }
        PolicyAction::Create { name, policy_type } => {
            println!("kitepass policy create: name={name}, type={policy_type}");
        }
        PolicyAction::Get { policy_id } => {
            println!("kitepass policy get: {policy_id}");
        }
        PolicyAction::Activate { policy_id } => {
            println!("kitepass policy activate: {policy_id}");
        }
        PolicyAction::Deactivate { policy_id } => {
            println!("kitepass policy deactivate: {policy_id}");
        }
    }
    Ok(())
}
