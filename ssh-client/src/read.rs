use anyhow::Result;
use std::io::Read;
use std::net::TcpStream;

pub fn read_exact(stream: &mut TcpStream, mac_len: usize) -> Result<Vec<u8>> {
    let mut packet_len = [0u8; 4];
    stream.read_exact(&mut packet_len)?;
    let packet_len_v = u32::from_be_bytes(packet_len);
    let mut packet_buf = vec![0u8; mac_len + packet_len_v as usize];
    stream.read_exact(packet_buf.as_mut_slice())?;
    Ok([&packet_len, packet_buf.as_slice()].concat())
}
