use crate::cli::SignAction;
use anyhow::Result;

pub async fn run(action: SignAction) -> Result<()> {
    match action {
        SignAction::Validate => {
            println!("kitepass sign validate (not yet implemented)");
        }
        SignAction::Submit => {
            println!("kitepass sign submit (not yet implemented)");
        }
    }
    Ok(())
}
