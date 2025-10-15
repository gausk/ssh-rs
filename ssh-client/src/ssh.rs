use crate::auth::{ServiceRequestType, SshMsgUserAuthRequest};
use crate::kex::{DerivedKeys, KexEcdhInitMsg, KexEcdhReplyMsg, MAC_VAL_LEN, get_nonce};
use aes_gcm::aead::Aead;
use aes_gcm::{AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce, Tag};
use anyhow::{Result, anyhow, bail};
use num_enum::TryFromPrimitive;
use rand::{Rng, rng};
use tracing::info;
use tracing_subscriber::fmt::FormatFields;

/// Binary Packet Protocol
///
/// Each packet is in the following format:
///
/// uint32    packet_length
/// byte      padding_length
/// byte[n1]  payload; n1 = packet_length - padding_length - 1
/// byte[n2]  random padding; n2 = padding_length
/// byte[m]   mac (Message Authentication Code - MAC); m = mac_length
///
/// packet_length
/// The length of the packet in bytes, not including 'mac' or the
/// 'packet_length' field itself.
///
/// padding_length
/// Length of 'random padding' (bytes).
///
/// payload
/// The useful contents of the packet.  If compression has been
/// negotiated, this field is compressed.  Initially, compression
/// MUST be "none".
///
/// random padding
/// Arbitrary-length padding, such that the total length of
/// (packet_length || padding_length || payload || random padding)
/// is a multiple of the cipher block size or 8, whichever is
/// larger.  There MUST be at least four bytes of padding.  The
/// padding SHOULD consist of random bytes.  The maximum amount of
/// padding is 255 bytes.
///
/// mac
/// Message Authentication Code.  If message authentication has
/// been negotiated, this field contains the MAC bytes.  Initially,
/// the MAC algorithm MUST be "none".
/// SSHPacket {
///     packet_length: 1164,
///     padding_length: 10,
///     payload: SSHPacketData::SshMsgKexInit(
///         KexInitMsg {
///             cookie: [
///                 69, 49, 64, 234, 72, 53, 70, 58, 61, 22, 184, 150, 189, 56, 222, 229
///             ],
///             kex: [
///                 "ecdh-sha2-nistp256",
///                 "sntrup761x25519-sha512",
///                 "sntrup761x25519-sha512@openssh.com",
///                 "mlkem768x25519-sha256",
///                 "curve25519-sha256",
///                 "curve25519-sha256@libssh.org",
///                 "ecdh-sha2-nistp384",
///                 "ecdh-sha2-nistp521",
///                 "diffie-hellman-group-exchange-sha256",
///                 "diffie-hellman-group16-sha512",
///                 "diffie-hellman-group18-sha512",
///                 "diffie-hellman-group14-sha256",
///                 "ext-info-s",
///                 "kex-strict-s-v00@openssh.com"
///             ],
///             shk: ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
///             encryption_cs: [
///                 "aes128-gcm@openssh.com",
///                 "aes256-gcm@openssh.com",
///                 "chacha20-poly1305@openssh.com",
///                 "aes128-ctr",
///                 "aes192-ctr",
///                 "aes256-ctr"
///             ],
///             encryption_sc: [
///                 "aes128-gcm@openssh.com",
///                 "aes256-gcm@openssh.com",
///                 "chacha20-poly1305@openssh.com",
///                 "aes128-ctr",
///                 "aes192-ctr",
///                 "aes256-ctr"
///             ],
///             mac_cs: [
///                 "hmac-sha2-256-etm@openssh.com",
///                 "hmac-sha2-256",
///                 "umac-64-etm@openssh.com",
///                 "umac-128-etm@openssh.com",
///                 "hmac-sha2-512-etm@openssh.com",
///                 "hmac-sha1-etm@openssh.com",
///                 "umac-64@openssh.com",
///                 "umac-128@openssh.com",
///                 "hmac-sha2-512",
///                 "hmac-sha1"
///             ],
///             mac_sc: [
///                 "hmac-sha2-256-etm@openssh.com",
///                 "hmac-sha2-256",
///                 "umac-64-etm@openssh.com",
///                 "umac-128-etm@openssh.com",
///                 "hmac-sha2-512-etm@openssh.com",
///                 "hmac-sha1-etm@openssh.com",
///                 "umac-64@openssh.com",
///                 "umac-128@openssh.com",
///                 "hmac-sha2-512",
///                 "hmac-sha1"
///             ],
///             compression_cs: ["none", "zlib@openssh.com"],
///             compression_sc: ["none", "zlib@openssh.com"],
///             languages_cs: [""],
///             languages_sc: [""],
///             first_kex_follow: false,
///             reserved: 0
///         }
///     ),
///     padding: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
///     mac: []
/// }
#[derive(Debug, Clone)]
pub struct SSHPacket {
    packet_length: u32,
    padding_length: u8,
    pub payload: SSHPacketData,
    padding: Vec<u8>,
    mac: Vec<u8>,
}

impl SSHPacket {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            bail!("Data too short to contain SSH packet header");
        }
        let packet_length = u32::from_be_bytes(data[0..4].try_into()?);
        let padding_length = data[4];
        let mut offset = 5;
        let payload_len = packet_length as usize - padding_length as usize - 1;
        if offset + payload_len + padding_length as usize > data.len() {
            bail!("SSH packet too small for payload + padding");
        }
        let payload = SSHPacketData::from_bytes(&data[offset..offset + payload_len])?;
        offset += payload_len;
        let padding = data[offset..offset + padding_length as usize].to_vec();
        offset += padding_length as usize;
        let mac = if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            packet_length,
            padding_length,
            payload,
            padding,
            mac,
        })
    }

    pub fn from_encrypted_bytes(
        data: &mut [u8],
        all_keys: &DerivedKeys,
        seq_no: u64,
    ) -> Result<Self> {
        let packet_length = u32::from_be_bytes(data[..4].try_into()?);
        let expected_data_len = 4 + packet_length as usize + MAC_VAL_LEN;
        if expected_data_len != data.len() {
            bail!(
                "Encrypted packet length mismatch, expected {} got {}",
                expected_data_len,
                data.len()
            );
        }
        let nonce = get_nonce(&all_keys.server_iv, seq_no)?;
        let nonce = Nonce::from_slice(&nonce);
        let key = Key::<Aes128Gcm>::from_slice(&all_keys.server_key);
        let cipher = Aes128Gcm::new(key);
        let tag = Tag::from_iter(data[expected_data_len - MAC_VAL_LEN..].to_vec());
        let aad = data[..4].to_vec();
        cipher
            .decrypt_in_place_detached(
                nonce,
                &aad,
                &mut data[4..expected_data_len - MAC_VAL_LEN],
                &tag,
            )
            .map_err(|e| anyhow!("Failed to decrypt packet, error: {}", e))?;
        SSHPacket::from_bytes(data)
    }

    pub fn from_payload(payload: SSHPacketData, is_encrypted: bool) -> Self {
        let payload_bytes = payload.to_bytes();
        let payload_len = payload_bytes.len();
        let block_size = 16;
        let include_packet_length = if is_encrypted {
            // RFC 5647
            // the random_padding MUST be at least 4 octets in length but no more than 255 octets.
            // The total length of the PT MUST be a multiple of 16 octets (the block size of AES).
            // PT (padding length + payload + padding)
            0
        } else {
            // Note that the length of the concatenation of 'packet_length',
            // 'padding_length', 'payload', and 'random padding' MUST be a multiple
            // of the cipher block size or 8, whichever is larger
            4
        };
        // +1 for padding_length byte
        // +4 for packet_length
        let mut padding_length =
            block_size - ((payload_len + 1 + include_packet_length) % block_size);
        if padding_length < 4 {
            padding_length += block_size; // min padding 4
        }
        let packet_length = (payload_len + 1 + padding_length) as u32;
        let mut padding = vec![0u8; padding_length];
        rng().fill(&mut padding[..]);
        Self {
            packet_length,
            padding_length: padding_length as u8,
            payload,
            padding,
            mac: vec![],
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.len());
        output.extend(self.packet_length.to_be_bytes());
        output.push(self.padding_length);
        output.extend(self.payload.to_bytes());
        output.extend(self.padding);
        output.extend(self.mac);
        output
    }

    /// RFC 5647 (Sec 7.2)
    /// In AES-GCM secure shell, the inputs to the authenticated encryption are:
    ///
    ///      PT (Plain Text)
    ///         byte      padding_length; // 4 <= padding_length < 256
    ///         byte[n1]  payload;        // n1 = packet_length-padding_length-1
    ///         byte[n2]  random_padding; // n2 = padding_length
    ///      AAD (Additional Authenticated Data)
    ///         uint32    packet_length;  // 0 <= packet_length < 2^32
    ///      IV (Initialization Vector)
    ///         As described in section 7.1.
    ///      BK (Block Cipher Key)
    ///         The appropriate Encryption Key formed during the Key Exchange.
    ///
    /// As required in [RFC4253], the random_padding MUST be at least 4
    /// octets in length but no more than 255 octets.  The total length of
    /// the PT MUST be a multiple of 16 octets (the block size of AES).  The
    /// binary packet is the concatenation of the 4-octet packet_length, the
    /// cipher text (CT), and the 16-octet authentication tag (AT).*/
    pub fn to_encrypted_bytes(self, all_keys: &DerivedKeys, seq_no: u64) -> Result<Vec<u8>> {
        let mut data = self.to_bytes();
        let key = Key::<Aes128Gcm>::from_slice(all_keys.client_key.as_slice());
        let cipher = Aes128Gcm::new(key);
        let nonce = get_nonce(all_keys.client_iv.as_slice(), seq_no)?;
        let nonce = Nonce::from_slice(&nonce);
        let aad = data[..4].to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, &mut data[4..])
            .unwrap();
        data.extend(tag);
        Ok(data)
    }

    fn len(&self) -> usize {
        4 + self.packet_length as usize + self.mac.len()
    }
}

#[derive(Debug, Clone)]
pub enum SSHPacketData {
    SshMsgKexInit(KexInitMsg),
    SshMsgKexEcdhInit(KexEcdhInitMsg),
    SshMsgKexEcdhReply(KexEcdhReplyMsg),
    SshMsgNewKeys,
    SshMsgServiceRequest(ServiceRequestType),
    SshMsgServiceAccept(ServiceRequestType),
    SshMsgUserAuthRequest(SshMsgUserAuthRequest),
    SshMsgUserAuthSuccess,
}

impl SSHPacketData {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            bail!("Data too short to read ssh packet type");
        }
        let packet_type = SSHPacketType::try_from(data[0])?;
        Ok(match packet_type {
            SSHPacketType::SshMsgKexInit => {
                Self::SshMsgKexInit(KexInitMsg::from_bytes(&data[1..])?)
            }
            SSHPacketType::SshMsgKexEcdhInit => unreachable!(),
            SSHPacketType::SshMsgKexEcdhReply => {
                SSHPacketData::SshMsgKexEcdhReply(KexEcdhReplyMsg::from_bytes(&data[1..])?)
            }
            SSHPacketType::SshMsgNewKeys => SSHPacketData::SshMsgNewKeys,
            SSHPacketType::SshMsgServiceRequest => {
                SSHPacketData::SshMsgServiceRequest(ServiceRequestType::from_bytes(&data[1..])?)
            }
            SSHPacketType::SshMsgServiceAccept => {
                SSHPacketData::SshMsgServiceAccept(ServiceRequestType::from_bytes(&data[1..])?)
            }
            SSHPacketType::SshMsgUserAuthRequest => unreachable!(),
            SSHPacketType::SshMsgUserAuthSuccess => SSHPacketData::SshMsgUserAuthSuccess,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SSHPacketData::SshMsgKexInit(packet) => packet.to_bytes(),
            SSHPacketData::SshMsgKexEcdhInit(packet) => packet.to_bytes(),
            SSHPacketData::SshMsgKexEcdhReply(_) => unreachable!(),
            SSHPacketData::SshMsgNewKeys => vec![SSHPacketType::SshMsgNewKeys as u8],
            SSHPacketData::SshMsgServiceRequest(typ) => {
                let mut data = Vec::new();
                data.push(SSHPacketType::SshMsgServiceRequest as u8);
                data.extend(typ.to_bytes());
                data
            }
            SSHPacketData::SshMsgServiceAccept(typ) => {
                let mut data = Vec::new();
                data.push(SSHPacketType::SshMsgServiceAccept as u8);
                data.extend(typ.to_bytes());
                data
            }
            SSHPacketData::SshMsgUserAuthRequest(req) => req.to_bytes(),
            SSHPacketData::SshMsgUserAuthSuccess => {
                vec![SSHPacketType::SshMsgUserAuthSuccess as u8]
            }
        }
    }

    pub fn get_kex_ecdh_reply(&self) -> &KexEcdhReplyMsg {
        match self {
            SSHPacketData::SshMsgKexEcdhReply(x) => x,
            SSHPacketData::SshMsgKexInit(_)
            | SSHPacketData::SshMsgKexEcdhInit(_)
            | SSHPacketData::SshMsgNewKeys
            | SSHPacketData::SshMsgServiceRequest(_)
            | SSHPacketData::SshMsgServiceAccept(_)
            | SSHPacketData::SshMsgUserAuthRequest(_)
            | SSHPacketData::SshMsgUserAuthSuccess => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum SSHPacketType {
    SshMsgServiceRequest = 5,
    SshMsgServiceAccept = 6,
    SshMsgKexInit = 20,
    SshMsgNewKeys = 21,
    SshMsgKexEcdhInit = 30,
    SshMsgKexEcdhReply = 31,
    SshMsgUserAuthRequest = 50,
    SshMsgUserAuthSuccess = 52,
}

/// Key exchange begins by each side sending the following packet:
///
/// byte         SSH_MSG_KEXINIT
/// byte[16]     cookie (random bytes)
/// name-list    kex_algorithms
/// name-list    server_host_key_algorithms
/// name-list    encryption_algorithms_client_to_server
/// name-list    encryption_algorithms_server_to_client
/// name-list    mac_algorithms_client_to_server
/// name-list    mac_algorithms_server_to_client
/// name-list    compression_algorithms_client_to_server
/// name-list    compression_algorithms_server_to_client
/// name-list    languages_client_to_server
/// name-list    languages_server_to_client
/// boolean      first_kex_packet_follows
/// uint32       0 (reserved for future extension)
///
/// Each of the algorithm name-lists MUST be a comma-separated list of
/// algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
/// information in [SSH-NUMBERS]).  Each supported (allowed) algorithm
/// MUST be listed in order of preference, from most to least.
///
/// first_kex_packet_follows
/// Indicates whether a guessed key exchange packet follows.  If a
/// guessed packet will be sent, this MUST be TRUE.  If no guessed
/// packet will be sent, this MUST be FALSE.
///
/// After receiving the SSH_MSG_KEXINIT packet from the other side,
/// each party will know whether their guess was right.  If the
/// other party's guess was wrong, and this field was TRUE, the
/// next packet MUST be silently ignored, and both sides MUST then
/// act as determined by the negotiated key exchange method.  If
/// the guess was right, key exchange MUST continue using the
/// guessed packet.
#[derive(Debug, Clone)]
pub struct KexInitMsg {
    pub cookie: Vec<u8>,
    pub kex: Vec<String>,
    pub shk: Vec<String>,
    pub encryption_cs: Vec<String>,
    pub encryption_sc: Vec<String>,
    pub mac_cs: Vec<String>,
    pub mac_sc: Vec<String>,
    pub compression_cs: Vec<String>,
    pub compression_sc: Vec<String>,
    pub languages_cs: Vec<String>,
    pub languages_sc: Vec<String>,
    pub first_kex_follow: bool,
    pub reserved: u32,
}

impl KexInitMsg {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let cookie_len = 16;
        if offset + cookie_len > data.len() {
            bail!("Data too short to contain cookie");
        }
        let cookie = data[offset..offset + cookie_len].to_vec();
        offset += cookie_len;
        let kex = read_name_list(data, &mut offset)?;
        let shk = read_name_list(data, &mut offset)?;
        let encryption_cs = read_name_list(data, &mut offset)?;
        let encryption_sc = read_name_list(data, &mut offset)?;
        let mac_cs = read_name_list(data, &mut offset)?;
        let mac_sc = read_name_list(data, &mut offset)?;
        let compression_cs = read_name_list(data, &mut offset)?;
        let compression_sc = read_name_list(data, &mut offset)?;
        let languages_cs = read_name_list(data, &mut offset)?;
        let languages_sc = read_name_list(data, &mut offset)?;
        if offset >= data.len() {
            bail!("data too short to contain first_kex_follow");
        }
        let first_kex_follow = data[offset] != 0x00;
        offset += 1;
        if offset + 4 > data.len() {
            bail!("data too short to contain reserved");
        }
        let reserved = u32::from_be_bytes(data[offset..offset + 4].try_into()?);
        Ok(Self {
            cookie,
            kex,
            shk,
            encryption_cs,
            encryption_sc,
            mac_cs,
            mac_sc,
            compression_cs,
            compression_sc,
            languages_cs,
            languages_sc,
            first_kex_follow,
            reserved,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(SSHPacketType::SshMsgKexInit as u8);
        output.extend_from_slice(self.cookie.as_slice());

        for name_list in [
            &self.kex,
            &self.shk,
            &self.encryption_cs,
            &self.encryption_sc,
            &self.mac_cs,
            &self.mac_sc,
            &self.compression_cs,
            &self.compression_sc,
            &self.languages_cs,
            &self.languages_sc,
        ] {
            let names = name_list.join(",");
            let name_bytes = names.as_bytes();
            output.extend((name_bytes.len() as u32).to_be_bytes());
            output.extend_from_slice(name_bytes);
        }
        output.push(self.first_kex_follow as u8);
        output.extend(self.reserved.to_be_bytes());
        output
    }
}

impl Default for KexInitMsg {
    fn default() -> Self {
        Self {
            cookie: rng().random::<[u8; 16]>().to_vec(),
            kex: vec!["ecdh-sha2-nistp256".to_string()],
            shk: vec!["rsa-sha2-256".to_string()],
            encryption_cs: vec!["aes128-gcm@openssh.com".to_string()],
            encryption_sc: vec!["aes128-gcm@openssh.com".to_string()],
            mac_cs: vec!["hmac-sha2-256".to_string()],
            mac_sc: vec!["hmac-sha2-256".to_string()],
            compression_cs: vec!["none".to_string()],
            compression_sc: vec!["none".to_string()],
            languages_cs: vec!["".to_string()],
            languages_sc: vec!["".to_string()],
            first_kex_follow: false,
            reserved: 0,
        }
    }
}

fn read_name_list(data: &[u8], offset: &mut usize) -> Result<Vec<String>> {
    if *offset + 4 > data.len() {
        bail!("Data too short to contain name list");
    }
    let data_len = u32::from_be_bytes(data[*offset..*offset + 4].try_into()?) as usize;
    *offset += 4;
    if *offset + data_len > data.len() {
        bail!("Data too short to contain name list");
    }
    let names = String::from_utf8_lossy(&data[*offset..*offset + data_len])
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    *offset += data_len;
    Ok(names)
}
