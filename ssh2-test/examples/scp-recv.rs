use anyhow::Result;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;

fn main() -> Result<()> {
    let stream = TcpStream::connect("127.0.0.1:22")?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(stream);
    sess.handshake()?;
    sess.userauth_agent("gautamkumar")?;
    println!("Authentication status: {}", sess.authenticated());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/local-sent.txt");
    let (mut channel, stat) = sess.scp_recv(&path)?;
    println!("Received file size: {}", stat.size());
    let mut buf = String::new();
    channel.read_to_string(&mut buf)?;
    println!("Data from the file: {}", buf);
    channel.send_eof()?;
    channel.wait_eof()?;
    channel.close()?;
    channel.wait_close()?;
    Ok(())
}
