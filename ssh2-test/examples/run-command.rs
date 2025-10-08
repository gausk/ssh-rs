use std::net::TcpStream;
use std::io::Read;
use anyhow::Result;
use ssh2::Session;

fn main() -> Result<()> {
    let stream = TcpStream::connect("127.0.0.1:22")?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(stream);
    sess.handshake()?;
    sess.userauth_agent("gautamkumar")?;
    println!("Authentication status: {}", sess.authenticated());
    let mut channel = sess.channel_session()?;
    channel.exec("ls -ltr")?;
    let mut buff = String::new();
    channel.read_to_string(&mut buff)?;
    println!("Output of ls -ltr:\n{}", buff);
    Ok(())
}