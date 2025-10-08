use anyhow::Result;
use ssh2::Session;
use std::env;
use std::net::TcpStream;

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        println!("Usage: {} <password>", args[0]);
        std::process::exit(1);
    }
    let stream = TcpStream::connect("localhost:22")?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(stream);
    sess.handshake()?;
    sess.userauth_password("gautamkumar", args[1].as_str())?;
    println!(
        "Password based authentication result: {}",
        sess.authenticated()
    );
    Ok(())
}
