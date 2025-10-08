use std::net::TcpStream;
use anyhow::Result;
use ssh2::Session;

fn main() -> Result<()> {
    let stream = TcpStream::connect("127.0.0.1:22")?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(stream);
    sess.handshake()?;
    sess.userauth_agent("gautamkumar")?;
    println!("Authentication status: {}", sess.authenticated());
    Ok(())
}