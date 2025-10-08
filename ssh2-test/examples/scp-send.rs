use anyhow::Result;
use ssh2::Session;
use std::io::Write;
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
    let mut channel = sess.scp_send(&path, 0o644, 10, None)?;
    channel.write(b"Hello, GK!")?;
    channel.send_eof()?;
    channel.wait_eof()?;
    channel.close()?;
    channel.wait_close()?;
    Ok(())
}
