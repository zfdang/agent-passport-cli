use crate::cli::OperationsAction;
use anyhow::Result;

pub async fn run(action: OperationsAction) -> Result<()> {
    match action {
        OperationsAction::Get { operation_id } => {
            println!("kitepass operations get: {operation_id}");
        }
    }
    Ok(())
}
