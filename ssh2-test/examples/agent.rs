use ssh2::Session;
use anyhow::Result;

fn main() -> Result<()> {
    let sess = Session::new()?;
    let mut agent = sess.agent()?;
    agent.connect()?;
    agent.list_identities()?;

    for identity in agent.identities()? {
        println!("Identity: {:?}", identity.comment());
        identity.blob();
    }
    Ok(())
}