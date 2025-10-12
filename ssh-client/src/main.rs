use anyhow::Result;
use ssh_client::auth::ServiceRequestType;
use ssh_client::kex::{
    DerivedKeys, KexEcdhInitMsg, calcualte_exchange_hash, calculate_shared_secret,
    generate_kex_pair,
};
use ssh_client::read::read_exact;
use ssh_client::ssh::{KexInitMsg, SSHPacket, SSHPacketData};
use std::io::{Read, Write};
use std::net::TcpStream;
use tracing::{info, subscriber};
use tracing_subscriber::FmtSubscriber;

fn main() -> Result<()> {
    subscriber::set_global_default(FmtSubscriber::new())?;
    let mut stream = TcpStream::connect("127.0.0.1:22")?;
    info!("Connected to the server");
    let mut buf = [0; 4096];
    // 1. When the connection has been established, both sides MUST send an identification
    // string of form SSH-protoversion-softwareversion SP comments CR LF
    let rlen = stream.read(&mut buf)?;
    let server_ident = buf[..rlen - 2].to_vec();
    info!(
        "Server identification string: {}",
        String::from_utf8_lossy(&server_ident)
    );
    let mut client_ident = b"SSH-2.0-GauravSSH_0.1\r\n".as_slice();
    stream.write_all(client_ident)?;
    stream.flush()?;
    // remove \r\n
    client_ident = &client_ident[..client_ident.len() - 2];

    // 2. SSH_MSG_KEXINIT
    let mut seq_in = 0;
    let mut seq_out = 0;
    let rlen = stream.read(&mut buf)?;
    let server_kex_init = SSHPacket::from_bytes(&buf[..rlen])?;
    seq_in += 1;
    info!("Server KEXINIT: {:?}", server_kex_init);
    let server_kex_init_payload = server_kex_init.payload.to_bytes();
    let client_kex_init =
        SSHPacket::from_payload(SSHPacketData::SshMsgKexInit(KexInitMsg::default()));
    let client_kex_init_payload = client_kex_init.payload.to_bytes();
    stream.write_all(&client_kex_init.to_bytes())?;
    stream.flush()?;
    seq_out += 1;

    // 3. SSH_MSG_KEX_ECDH_INIT
    let (client_pvt_key, client_pubkey) = generate_kex_pair();
    let kex_ecdh_init = SSHPacket::from_payload(SSHPacketData::SshMsgKexEcdhInit(
        KexEcdhInitMsg::new(&client_pubkey),
    ));
    stream.write_all(&kex_ecdh_init.to_bytes())?;
    stream.flush()?;
    seq_out += 1;

    // 4. SSH_MSG_KEX_ECDH_REPLY
    let ecdh_reply_buf = read_exact(&mut stream, 0)?;
    seq_in += 1;
    let ecdh_reply = SSHPacket::from_bytes(&ecdh_reply_buf)?;
    let reply_msg = ecdh_reply.payload.get_kex_ecdh_reply();
    let server_phk = reply_msg.host_key.as_ref();
    let server_ephemral_pk = reply_msg.server_pubkey.as_ref();
    info!("ECHDH reply: {:?}", ecdh_reply);

    // 5. TODO: Verify received keys are valid.

    // 6. TODO: Validate Host key of the server is signed by a valid CA

    // 7. Generate shared secret
    let shared_secret = calculate_shared_secret(&client_pvt_key, server_ephemral_pk)?;
    let ex_hash = calcualte_exchange_hash(
        client_ident,
        &server_ident,
        &client_kex_init_payload,
        &server_kex_init_payload,
        server_phk,
        &client_pubkey,
        server_ephemral_pk,
        &shared_secret,
    );
    info!("ex hash: {:?}", ex_hash);
    let all_keys = DerivedKeys::derive(&shared_secret, &ex_hash, &ex_hash);

    // 10. Send and recv SSH2_MSG_NEWKEYS
    let ssh_msg_new_keys = SSHPacket::from_payload(SSHPacketData::SshMsgNewKeys);
    stream.write_all(&ssh_msg_new_keys.to_bytes())?;
    stream.flush()?;
    seq_out += 1;

    let rlen = stream.read(&mut buf)?;
    seq_in += 1;
    let server_ssh_msg_new_keys = SSHPacket::from_bytes(&buf[..rlen])?;
    info!("server SSH2_MSG_NEWKEYS: {:?}", server_ssh_msg_new_keys);

    // 11. Send SSH_MSG_SERVICE_REQUEST
    let client_ssh_service_request = SSHPacket::from_payload(SSHPacketData::SshMsgServiceRequest(
        ServiceRequestType::SshUserauth,
    ));
    stream.write_all(&client_ssh_service_request.to_encrypted_bytes(&all_keys, seq_out))?;
    stream.flush()?;
    //seq_out += 1;

    // 12. Recv SSH_MSG_SERVICE_ACCEPT
    let rlen = stream.read(&mut buf)?;
    let server_ssh_msg_new_keys = SSHPacket::from_encrypted_bytes(&buf[..rlen], &all_keys, seq_in)?;
    //seq_in += 1;
    info!("Recv accept message: {:?}", server_ssh_msg_new_keys);
    Ok(())
}
