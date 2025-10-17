use crate::ssh::SSHPacketType;
use anyhow::{Result, bail};

/// Disconnection Message
///
/// byte      SSH_MSG_DISCONNECT
/// uint32    reason code
/// string    description in ISO-10646 UTF-8 encoding `[`RFC3629`]`
/// string    language tag `[`RFC3066`]`
///
/// This message causes immediate termination of the connection.  All
/// implementations MUST be able to process this message; they SHOULD be
/// able to send this message.
#[derive(Debug, Clone)]
pub struct SshMsgDisconnect {
    reason_code: u32,
    description: String,
    language_tag: String,
}

impl Default for SshMsgDisconnect {
    fn default() -> Self {
        Self {
            reason_code: 10, // SSH_DISCONNECT_BY_APPLICATION
            description: "Done with everything".to_string(),
            language_tag: "English".to_string(),
        }
    }
}

impl SshMsgDisconnect {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 + 4 + 4 {
            bail!("SSH disconnect message too short");
        }
        let reason_code = u32::from_be_bytes(buf[..4].try_into()?);
        let mut offset = 4;
        let description_len = u32::from_be_bytes(buf[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        if offset + description_len > buf.len() {
            bail!("SSH disconnect message too short to read description");
        }
        let description =
            String::from_utf8_lossy(&buf[offset..offset + description_len]).to_string();
        offset += description_len;
        if offset + 4 > buf.len() {
            bail!("SSH disconnect message too short to read language");
        }
        let language_len = u32::from_be_bytes(buf[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        if offset + language_len > buf.len() {
            bail!("SSH disconnect message too short to read language");
        }
        let language_tag = String::from_utf8_lossy(&buf[offset..offset + language_len]).to_string();
        Ok(Self {
            reason_code,
            description,
            language_tag,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SSHPacketType::SshMsgDisconnect as u8);
        out.extend_from_slice(&self.reason_code.to_be_bytes());
        let desc_bytes = self.description.as_bytes();
        out.extend(&(desc_bytes.len() as u32).to_be_bytes());
        out.extend(desc_bytes);

        let lang_bytes = self.language_tag.as_bytes();
        out.extend(&(lang_bytes.len() as u32).to_be_bytes());
        out.extend(lang_bytes);

        out
    }
}
