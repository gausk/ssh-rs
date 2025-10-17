use anyhow::Result;
use clap::Parser;
use ssh_client::auth::{ServiceRequestType, SshMsgUserAuthRequest};
use ssh_client::channel::{
    RequestType, SshMsgChannelOpenReq, SshMsgChannelReq, SshMsgChannelWindowAdjust,
};
use ssh_client::disconnect::SshMsgDisconnect;
use ssh_client::kex::{
    DerivedKeys, KexEcdhInitMsg, MAC_VAL_LEN, calculate_exchange_hash, calculate_shared_secret,
    generate_kex_pair,
};
use ssh_client::read::read_exact;
use ssh_client::ssh::{KexInitMsg, SSHPacket, SSHPacketData};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;
use tracing::{info, subscriber};
use tracing_subscriber::FmtSubscriber;

fn vec_to_string_or_hex(data: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(data) {
        // Only print as text if it's mostly printable ASCII
        if s.chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return s.to_string();
        }
    }
    hex::encode(data)
}

fn dump_vec(label: &str, data: &[u8]) {
    info!(
        "{} ({} bytes): {}",
        label,
        data.len(),
        vec_to_string_or_hex(data)
    );
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[clap(short, long, default_value = "127.0.0.1")]
    server_ip: String,
    #[clap(short, long, default_value = "22")]
    port: u16,
    #[clap(short, long, default_value = "gautamkumar")]
    username: String,
}

fn main() -> Result<()> {
    subscriber::set_global_default(FmtSubscriber::new())?;
    let args = Args::parse();

    let mut stream = TcpStream::connect(format!("{}:{}", args.server_ip, args.port))?;
    info!(
        "Connected to the server at ip: {} and port: {}",
        args.server_ip, args.port
    );
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
    dump_vec("Client identification string", client_ident);

    // 2. SSH_MSG_KEXINIT
    let rlen = stream.read(&mut buf)?;
    let server_kex_init = SSHPacket::from_bytes(&buf[..rlen])?;
    info!("Server KEXINIT: {:?}", server_kex_init);
    let server_kex_init_payload = server_kex_init.payload.to_bytes();

    let client_kex_init =
        SSHPacket::from_payload(SSHPacketData::SshMsgKexInit(KexInitMsg::default()), false);
    let client_kex_init_payload = client_kex_init.payload.to_bytes();
    info!("Client KEXINIT {:?}", client_kex_init);
    stream.write_all(&client_kex_init.to_bytes())?;
    stream.flush()?;

    // 3. SSH_MSG_KEX_ECDH_INIT
    let (client_pvt_key, client_pubkey) = generate_kex_pair();

    let kex_ecdh_init = SSHPacket::from_payload(
        SSHPacketData::SshMsgKexEcdhInit(KexEcdhInitMsg::new(&client_pubkey)),
        false,
    );
    info!("Client KEX_ECDH_INIT {:?}", kex_ecdh_init);
    stream.write_all(&kex_ecdh_init.to_bytes())?;
    stream.flush()?;

    // 4. SSH_MSG_KEX_ECDH_REPLY
    let ecdh_reply_buf = read_exact(&mut stream, 0)?;
    let ecdh_reply = SSHPacket::from_bytes(&ecdh_reply_buf)?;
    info!("Server ECDH_REPLY: {:?}", ecdh_reply);
    let reply_msg = ecdh_reply.payload.get_kex_ecdh_reply();
    let server_phk = reply_msg.host_key.as_ref();
    let server_ephemral_pk = reply_msg.server_pubkey.as_ref();
    dump_vec("server_ephemeral", server_ephemral_pk);
    dump_vec("client_ephemeral", &client_pubkey);
    dump_vec("host_key", server_phk);

    // 5. TODO: Verify received keys are valid.

    // 6. TODO: Validate Host key of the server is signed by a valid CA

    // 7. Generate shared secret
    let shared_secret = calculate_shared_secret(&client_pvt_key, server_ephemral_pk)?;
    let ex_hash = calculate_exchange_hash(
        client_ident,
        &server_ident,
        &client_kex_init_payload,
        &server_kex_init_payload,
        server_phk,
        &client_pubkey,
        server_ephemral_pk,
        &shared_secret,
    );
    dump_vec("ex_hash", &ex_hash);
    dump_vec("shared_secret", shared_secret.raw_secret_bytes().as_slice());
    info!("ex hash: {:?}", ex_hash);
    let all_keys = DerivedKeys::derive(&shared_secret, &ex_hash, &ex_hash);
    dump_vec("client_key", &all_keys.client_key);
    dump_vec("client_mac", &all_keys.client_mac);
    dump_vec("client_iv", &all_keys.client_iv);
    dump_vec("server_key", &all_keys.server_key);
    dump_vec("server_mac", &all_keys.server_mac);
    dump_vec("server_iv", &all_keys.server_iv);

    // 8. Send and recv SSH2_MSG_NEWKEYS
    let ssh_msg_new_keys = SSHPacket::from_payload(SSHPacketData::SshMsgNewKeys, false);
    info!("Client SSH2_MSG_NEWKEYS: {:?}", ssh_msg_new_keys);
    stream.write_all(&ssh_msg_new_keys.to_bytes())?;
    stream.flush()?;

    let rlen = stream.read(&mut buf)?;
    let server_ssh_msg_new_keys = SSHPacket::from_bytes(&buf[..rlen])?;
    info!("Server SSH2_MSG_NEWKEYS: {:?}", server_ssh_msg_new_keys);

    // 9. Send SSH_MSG_SERVICE_REQUEST
    // seq_out is encrypted packet sent count
    let mut seq_out = 0;
    let client_ssh_service_request = SSHPacket::from_payload(
        SSHPacketData::SshMsgServiceRequest(ServiceRequestType::SshUserauth),
        true,
    );
    info!(
        "Client SSH2_MSG_SERVICE_REQUEST {:?}",
        client_ssh_service_request
    );
    stream.write_all(&client_ssh_service_request.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    // 10. Recv SSH_MSG_SERVICE_ACCEPT
    // seq_in is encrypted packet received count
    let mut seq_in = 0;
    let rlen = stream.read(&mut buf)?;
    let server_ssh_msg_service_accept =
        SSHPacket::from_encrypted_bytes(&mut buf[..rlen], &all_keys, seq_in)?;
    seq_in += 1;
    info!(
        "Recv service accept message: {:?}",
        server_ssh_msg_service_accept
    );

    let password = rpassword::prompt_password("Your password: ")?;

    // 11. Send SSH_MSG_USERAUTH_REQUEST
    let client_auth_req = SSHPacket::from_payload(
        SSHPacketData::SshMsgUserAuthRequest(SshMsgUserAuthRequest::from_user_password(
            args.username.as_str(),
            password,
        )),
        true,
    );
    info!("Client auth request: {:?}", client_auth_req);
    stream.write_all(&client_auth_req.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    // 12. Recv SSH_MSG_USERAUTH_SUCCESS
    let rlen = stream.read(&mut buf)?;
    let auth_resp = SSHPacket::from_encrypted_bytes(&mut buf[..rlen], &all_keys, seq_in)?;
    seq_in += 1;
    info!("Recv auth response: {:?}", auth_resp);

    // 13. Send SSH_MSG_CHANNEL_OPEN
    let channel_open_req = SSHPacket::from_payload(
        SSHPacketData::SshMsgChannelOpen(SshMsgChannelOpenReq::default()),
        true,
    );
    info!("Client channel open req: {:?}", channel_open_req);
    stream.write_all(&channel_open_req.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    // 14. Recv SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    let recipient_channel: u32;
    loop {
        let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
        let recv_packet = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
        seq_in += 1;
        if let SSHPacketData::SshMsgChannelOpenConfirmation(_) = recv_packet.payload {
            info!("Recv channel open confirmation: {:?}", recv_packet);
            recipient_channel = recv_packet.payload.get_recipient_channel();
            break;
        } else {
            info!("Recv msg from server: {:?}", recv_packet);
        }
        sleep(Duration::from_secs(1));
    }

    // 15. Send SSH_MSG_CHANNEL_WINDOW_ADJUST
    let channel_window_adjust = SSHPacket::from_payload(
        SSHPacketData::SshMsgChannelWindowAdjust(SshMsgChannelWindowAdjust::new(recipient_channel)),
        true,
    );
    info!("Client channel_window_adjust: {:?}", channel_window_adjust);
    stream.write_all(&channel_window_adjust.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    // 16. Send SSH_MSG_CHANNEL_REQUEST
    let channel_req = SSHPacket::from_payload(
        SSHPacketData::SshMsgChannelRequest(SshMsgChannelReq::new(
            recipient_channel,
            RequestType::from_exec("ls -ltr", true),
        )),
        true,
    );
    info!("Client msg channel req: {:?}", channel_req);
    stream.write_all(&channel_req.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    // 17. Recv SSH_MSG_CHANNEL_WINDOW_ADJUST
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let recv_channel_window_adjust = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!(
        "Recv channel_window_adjust: {:?}",
        recv_channel_window_adjust
    );
    seq_in += 1;

    // 18. Recv SSH_MSG_CHANNEL_SUCCESS
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let channel_req_suc = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!("Recv channel success: {:?}", channel_req_suc);
    seq_in += 1;

    // 19. Recv SSH_MSG_CHANNEL_DATA
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let channel_data = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!("Recv channel data: {:?}", channel_data);
    seq_in += 1;

    // 20. Recv SSH_MSG_CHANNEL_EOF
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let channel_eof = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!("Recv channel eof: {:?}", channel_eof);
    seq_in += 1;

    // 21. Recv SSH_MSG_CHANNEL_REQUEST with exit-status
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let recv_channel_req = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!("Recv msg_channel_req: {:?}", recv_channel_req);
    seq_in += 1;

    // 22 Recv SSH_MSG_CHANNEL_CLOSE
    let mut data = read_exact(&mut stream, MAC_VAL_LEN)?;
    let channel_close = SSHPacket::from_encrypted_bytes(&mut data, &all_keys, seq_in)?;
    info!("Recv msg channel close: {:?}", channel_close);
    seq_in += 1;

    // 23 Send SSH_MSG_DISCONNECT
    let disconnect = SSHPacket::from_payload(
        SSHPacketData::SshMsgDisconnect(SshMsgDisconnect::default()),
        true,
    );
    info!("Send ssh disconnect: {:?}", disconnect);
    stream.write_all(&disconnect.to_encrypted_bytes(&all_keys, seq_out)?)?;
    stream.flush()?;
    seq_out += 1;

    info!("Encrypted packet sent {}", seq_out);
    info!("Encrypted packet received {}", seq_in);
    Ok(())
}
