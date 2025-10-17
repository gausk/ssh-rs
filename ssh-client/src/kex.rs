use crate::ssh::SSHPacketType;
use anyhow::{Result, bail};
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use rand_core::OsRng;
use sha2::Digest;
use sha2::Sha256;

/// hmac-sha2-256
pub const MAC_KEY_LEN: usize = 32;

/// aes128gcm
pub const MAC_VAL_LEN: usize = 16;

/// The following is an overview of the key exchange process:
///```text
/// Client                                                Server
/// ------                                                ------
/// Generate ephemeral key pair.
/// SSH_MSG_KEX_ECDH_INIT  -------------->
///
///                                                 Verify received key is valid.
///                                                 Generate ephemeral key pair.
///                                                 Compute shared secret.
///                                                 Generate and sign exchange hash.
///                                  <------------- SSH_MSG_KEX_ECDH_REPLY
///
/// Verify received key is valid.
/// *Verify host key belongs to server.
/// Compute shared secret.
/// Generate exchange hash.
/// Verify server's signature.
///```
/// It is RECOMMENDED that the client verify that the host key sent
/// is the server's host key (for example, using a local database).
/// The client MAY accept the host key without verification, but
/// doing so will render the protocol insecure against active
/// attacks; see the discussion in Section 4.1 of `[`RFC4251`]`.
///
pub fn generate_kex_pair() -> (EphemeralSecret, Box<[u8]>) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    (secret, public_key.to_sec1_bytes())
}

/// The client sends:
///
/// byte     SSH_MSG_KEX_ECDH_INIT
/// string   Q_C, client's ephemeral public key octet string
#[derive(Debug, Clone)]
pub struct KexEcdhInitMsg {
    pub pubkey: Vec<u8>,
}

impl KexEcdhInitMsg {
    pub fn new(pubkey: &[u8]) -> Self {
        Self {
            pubkey: pubkey.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SSHPacketType::SshMsgKexEcdhInit as u8);
        out.extend((self.pubkey.len() as u32).to_be_bytes());
        out.extend_from_slice(self.pubkey.as_slice());
        out
    }
}

/// The server responds with:
///
/// byte     SSH_MSG_KEX_ECDH_REPLY
/// string   K_S, server's public host key
/// string   Q_S, server's ephemeral public key octet string
/// string   the signature on the exchange hash
#[derive(Debug, Clone)]
pub struct KexEcdhReplyMsg {
    pub host_key: Vec<u8>,
    pub server_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl KexEcdhReplyMsg {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut offset = 0;
        Ok(Self {
            host_key: read_data_bytes(buf, &mut offset)?,
            server_pubkey: read_data_bytes(buf, &mut offset)?,
            signature: read_data_bytes(buf, &mut offset)?,
        })
    }
}

fn read_data_bytes(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset + 4 > buf.len() {
        bail!("buf length to short to read data");
    }
    let data_len = u32::from_be_bytes(buf[*offset..*offset + 4].try_into()?) as usize;
    *offset += 4;
    let data = buf[*offset..*offset + data_len].to_vec();
    *offset += data_len;
    Ok(data)
}

/// Using client secret key and server public key
/// d_C * Q_S = d_C * (d_S * G) = d_S * (d_C * G) = d_S * Q_C
pub fn calculate_shared_secret(
    client_pvt_key: &EphemeralSecret,
    server_pub_key: &[u8],
) -> Result<SharedSecret> {
    let public_key = PublicKey::from_sec1_bytes(server_pub_key)?;
    let shared_secret = client_pvt_key.diffie_hellman(&public_key);
    Ok(shared_secret)
}

/// The exchange hash H is computed as the hash of the concatenation of
/// the following.
///
/// string   V_C, client's identification string (CR and LF excluded)
/// string   V_S, server's identification string (CR and LF excluded)
/// string   I_C, payload of the client's SSH_MSG_KEXINIT
/// string   I_S, payload of the server's SSH_MSG_KEXINIT
/// string   K_S, server's public host key
/// string   Q_C, client's ephemeral public key octet string
/// string   Q_S, server's ephemeral public key octet string
/// mpint    K,   shared secret
///
/// For ecdh-sha2-nistp256, the hash function HASH is SHA-256.
#[allow(clippy::too_many_arguments)]
pub fn calculate_exchange_hash(
    cl_ident: &[u8],
    sr_ident: &[u8],
    cl_kexinit_payload: &[u8],
    sr_kexinit_payload: &[u8],
    sr_pub_host_key: &[u8],
    cl_ephemeral_pubkey: &[u8],
    sr_ephemeral_pubkey: &[u8],
    shared_secret: &SharedSecret,
) -> Vec<u8> {
    let mut data = Vec::new();
    for req in [
        cl_ident,
        sr_ident,
        cl_kexinit_payload,
        sr_kexinit_payload,
        sr_pub_host_key,
        cl_ephemeral_pubkey,
        sr_ephemeral_pubkey,
    ] {
        data.extend((req.len() as u32).to_be_bytes());
        data.extend_from_slice(req);
    }
    data.extend(encode_mpint(shared_secret));
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// mpint
///
/// Represents multiple precision integers in two's complement format,
/// stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// have the value 1 as the most significant bit of the first byte of
/// the data partition.  If the most significant bit would be set for
/// a positive number, the number MUST be preceded by a zero byte.
/// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
/// included.  The value zero MUST be stored as a string with zero
/// bytes of data.
///
/// By convention, a number that is used in modular computations in
/// Z_n SHOULD be represented in the range 0 <= x < n.
pub fn encode_mpint(shared_secret: &SharedSecret) -> Vec<u8> {
    let secret_raw = shared_secret.raw_secret_bytes().as_slice();
    let mut out = Vec::new();
    let mut i = 0;
    while i < secret_raw.len() && secret_raw[i] == 0 {
        i += 1
    }
    // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
    if secret_raw[i] & 0x80 != 0 {
        let len = (secret_raw.len() - i + 1) as u32;
        out.extend(len.to_be_bytes());
        out.push(0);
    } else {
        let len = (secret_raw.len() - i) as u32;
        out.extend(len.to_be_bytes());
    }
    out.extend_from_slice(&secret_raw[i..]);
    out
}

/// The key exchange produces two values: a shared secret K, and an
/// exchange hash H.  Encryption and authentication keys are derived from
/// these.  The exchange hash H from the first key exchange is
/// additionally used as the session identifier, which is a unique
/// identifier for this connection.  It is used by authentication methods
/// as a part of the data that is signed as a proof of possession of a
/// private key.  Once computed, the session identifier is not changed,
/// even if keys are later re-exchanged.
///
/// Each key exchange method specifies a hash function that is used in
/// the key exchange.  The same hash algorithm MUST be used in key
/// derivation.  Here, we'll call it HASH.
///
/// Encryption keys MUST be computed as HASH, of a known value and K, as
/// follows:
///
/// o  Initial IV client to server: HASH(K || H || "A" || session_id)
/// (Here K is encoded as mpint and "A" as byte and session_id as raw
/// data.  "A" means the single character A, ASCII 65).
///
/// o  Initial IV server to client: HASH(K || H || "B" || session_id)
///
/// o  Encryption key client to server: HASH(K || H || "C" || session_id)
///
/// o  Encryption key server to client: HASH(K || H || "D" || session_id)
///
/// o  Integrity key client to server: HASH(K || H || "E" || session_id)
///
/// o  Integrity key server to client: HASH(K || H || "F" || session_id)
///
/// Key data MUST be taken from the beginning of the hash output.  As
/// many bytes as needed are taken from the beginning of the hash value.
/// If the key length needed is longer than the output of the HASH, the
/// key is extended by computing HASH of the concatenation of K and H and
/// the entire key so far, and appending the resulting bytes (as many as
/// HASH generates) to the key.  This process is repeated until enough
/// key material is available; the key is taken from the beginning of
/// this value.  In other words:
///
/// K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
/// K2 = HASH(K || H || K1)
/// K3 = HASH(K || H || K1 || K2)
/// ...
/// key = K1 || K2 || K3 || ...
///
/// This process will lose entropy if the amount of entropy in K is
/// larger than the internal state size of HASH.
#[derive(Debug, Clone)]
pub struct DerivedKeys {
    pub client_iv: Vec<u8>,
    pub server_iv: Vec<u8>,
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
    pub client_mac: Vec<u8>,
    pub server_mac: Vec<u8>,
}

/// label is a single ASCII byte (b'A'..b'F').
/// The exchange hash H from the first key exchange is additionally used as
/// the session identifier, which is a unique identifier for this connection.
/// K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
/// K2 = HASH(K || H || K1)
/// K3 = HASH(K || H || K1 || K2)
/// ...
/// key = K1 || K2 || K3 || ...
fn derive_key(
    shared_secret: &SharedSecret,
    h: &[u8],
    label: u8,
    session_id: &[u8],
    desired_len: usize,
) -> Vec<u8> {
    let mut data = Vec::new();
    let encoded = encode_mpint(shared_secret);
    data.extend_from_slice(&encoded);
    data.extend_from_slice(h);
    data.push(label);
    data.extend_from_slice(session_id);
    let mut result = Sha256::digest(&data).to_vec(); // k1
    while result.len() < desired_len {
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.update(h);
        hasher.update(&result);
        result.extend(hasher.finalize().as_slice());
    }
    result.truncate(desired_len);
    result
}

impl DerivedKeys {
    /// SSH AES-GCM requires a 12-octet Initial IV and
    /// an encryption key of either 16 or 32 octets.  Because an AEAD
    /// algorithm such as AES-GCM uses the encryption key to provide both
    /// confidentiality and data integrity, the integrity key is not used
    /// with AES-GCM.
    pub fn derive(shared_secret: &SharedSecret, h: &[u8], session_id: &[u8]) -> DerivedKeys {
        // aes128-gcm@openssh.com
        let key_len = 16;
        let iv_len = 12;

        DerivedKeys {
            client_iv: derive_key(shared_secret, h, b'A', session_id, iv_len),
            server_iv: derive_key(shared_secret, h, b'B', session_id, iv_len),
            client_key: derive_key(shared_secret, h, b'C', session_id, key_len),
            server_key: derive_key(shared_secret, h, b'D', session_id, key_len),
            client_mac: derive_key(shared_secret, h, b'E', session_id, MAC_KEY_LEN),
            server_mac: derive_key(shared_secret, h, b'F', session_id, MAC_KEY_LEN),
        }
    }
}

/// RFC 5647(Sec 7.1)
/// With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
///    fixed field and an 8-octet invocation counter field.  The invocation
///    field is treated as a 64-bit integer and is incremented after each
///    invocation of AES-GCM to process a binary packet.
///```text
///          uint32  fixed;                  // 4 octets
///          uint64  invocation_counter;     // 8 octets
///```
pub fn get_nonce(iv: &[u8], seq_no: u64) -> Result<Vec<u8>> {
    let mut nonce = Vec::new();
    nonce.extend_from_slice(&iv[..4]);
    let invocation_counter = u64::from_be_bytes(iv[4..].try_into()?).wrapping_add(seq_no);
    nonce.extend(invocation_counter.to_be_bytes());
    Ok(nonce)
}
