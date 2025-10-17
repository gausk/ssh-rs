use crate::ssh::SSHPacketType;
use anyhow::{Result, bail};
use std::fmt::{Debug, Formatter};
use tracing::warn;

/// RFC 4254
/// Opening a Channel
///
/// When either side wishes to open a new channel, it allocates a local
/// number for the channel.  It then sends the following message to the
/// other side, and includes the local channel number and initial window
/// size in the message.
///
/// byte      SSH_MSG_CHANNEL_OPEN
/// string    channel type in US-ASCII only
/// uint32    sender channel
/// uint32    initial window size
/// uint32    maximum packet size
/// ....      channel type specific data follows
///
///
/// A session is started by sending the following message.
///
/// byte      SSH_MSG_CHANNEL_OPEN
/// string    "session"
/// uint32    sender channel
/// uint32    initial window size
/// uint32    maximum packet size
///
#[derive(Debug, Clone)]
pub struct SshMsgChannelOpenReq {
    pub channel_type: SshChannelType,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl Default for SshMsgChannelOpenReq {
    fn default() -> Self {
        Self {
            channel_type: SshChannelType::Session,
            sender_channel: 1,
            initial_window_size: 2097152, //2MB
            maximum_packet_size: 32768,   // 32KB
        }
    }
}
impl SshMsgChannelOpenReq {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SSHPacketType::SshMsgChannelOpen as u8);
        let channel_type = self.channel_type.as_str().as_bytes();
        buf.extend((channel_type.len() as u32).to_be_bytes());
        buf.extend_from_slice(channel_type);
        buf.extend(self.sender_channel.to_be_bytes());
        buf.extend(self.initial_window_size.to_be_bytes());
        buf.extend(self.maximum_packet_size.to_be_bytes());
        buf
    }
}

#[derive(Clone, Debug)]
pub enum SshChannelType {
    Session,
}

impl SshChannelType {
    pub fn as_str(&self) -> &str {
        match self {
            SshChannelType::Session => "session",
        }
    }
}

/// byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
/// uint32    recipient channel
/// uint32    sender channel
/// uint32    initial window size
/// uint32    maximum packet size
/// ....      channel type specific data follows
///
/// The 'recipient channel' is the channel number given in the original
/// open request, and 'sender channel' is the channel number allocated by
/// the other side.
#[derive(Clone, Debug)]
pub struct SshMsgChannelOpenConfirm {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl SshMsgChannelOpenConfirm {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            bail!("SshMsgChannelOpenConfirm: buffer too short");
        }
        if buf.len() > 16 {
            warn!(
                "SshMsgChannelOpenConfirm: received too long, extra data {}",
                String::from_utf8_lossy(&buf[16..])
            );
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
            sender_channel: u32::from_be_bytes(buf[4..8].try_into()?),
            initial_window_size: u32::from_be_bytes(buf[8..12].try_into()?),
            maximum_packet_size: u32::from_be_bytes(buf[12..16].try_into()?),
        })
    }
}

/// All such requests use the
/// following format.
///
/// byte      SSH_MSG_GLOBAL_REQUEST
/// string    request name in US-ASCII only
/// boolean   want reply
/// ....      request-specific data follows
#[derive(Clone, Debug)]
pub struct SshMsgGlobalRequest {
    pub request_name: String,
    pub want_reply: bool,
    pub request_specific: Vec<u8>,
}

impl SshMsgGlobalRequest {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            bail!("SshMsgGlobalRequest: buffer too short");
        }
        let request_name_len = u32::from_be_bytes(buf[..4].try_into()?) as usize;
        if 4 + request_name_len - 1 > buf.len() {
            bail!("SshMsgGlobalRequest: buffer too short");
        }
        let request_name = String::from_utf8_lossy(&buf[4..4 + request_name_len]).to_string();
        if buf[4 + request_name_len] > 1 {
            bail!("SshMsgGlobalRequest: want_reply should be either 0 or 1");
        }
        let want_reply = buf[4 + request_name_len] != 0;

        let request_specific = if buf.len() == 4 + request_name_len + 1 {
            Vec::new()
        } else {
            buf[4 + request_name_len + 1..].to_vec()
        };
        Ok(Self {
            request_name,
            want_reply,
            request_specific,
        })
    }
}

/// All channel-specific requests use the following format.
///
/// byte      SSH_MSG_CHANNEL_REQUEST
/// uint32    recipient channel
/// string    request type in US-ASCII characters only
/// boolean   want reply
/// ....      type-specific data follows
///
/// byte      SSH_MSG_CHANNEL_REQUEST
/// uint32    recipient channel
/// string    "exec"
/// boolean   want reply
/// string    command
///
/// This message will request that the server start the execution of the
/// given command.  The 'command' string may contain a path.  Normal
/// precautions MUST be taken to prevent the execution of unauthorized
/// commands.
///
/// The client MAY ignore these messages.
///
///      byte      SSH_MSG_CHANNEL_REQUEST
///      uint32    recipient channel
///      string    "exit-status"
///      boolean   FALSE
///      uint32    exit_status
#[derive(Clone, Debug)]
pub struct SshMsgChannelReq {
    pub recipient_channel: u32,
    pub request_type: RequestType,
}

impl SshMsgChannelReq {
    pub fn new(recipient_channel: u32, request_type: RequestType) -> Self {
        Self {
            recipient_channel,
            request_type,
        }
    }
}

impl SshMsgChannelReq {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SSHPacketType::SshMsgChannelRequest as u8);
        buf.extend(&self.recipient_channel.to_be_bytes());
        buf.extend(self.request_type.to_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            bail!("SshMsgChannelReq: buffer too short");
        }
        let recipient_channel = u32::from_be_bytes(buf[..4].try_into()?);
        let request_type = RequestType::from_bytes(&buf[4..])?;
        Ok(Self {
            recipient_channel,
            request_type,
        })
    }
}
#[derive(Clone, Debug)]
pub enum RequestType {
    Exec { command: String, want_reply: bool },
    ExitStatus { want_reply: bool, status_code: u32 },
}

impl RequestType {
    pub fn from_exec(command: &str, want_reply: bool) -> RequestType {
        RequestType::Exec {
            command: command.to_string(),
            want_reply,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            RequestType::Exec { .. } => "exec",
            RequestType::ExitStatus { .. } => "exit-status",
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let req_type = self.as_str().as_bytes();
        buf.extend((req_type.len() as u32).to_be_bytes());
        buf.extend_from_slice(req_type);
        match self {
            RequestType::Exec {
                command,
                want_reply,
            } => {
                buf.push(*want_reply as u8);
                let cmd = command.as_bytes();
                buf.extend((cmd.len() as u32).to_be_bytes());
                buf.extend_from_slice(cmd);
            }
            RequestType::ExitStatus {
                want_reply,
                status_code,
            } => {
                buf.push(*want_reply as u8);
                buf.extend(status_code.to_be_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            bail!("ReqType: buffer too short");
        }
        let mut offset = 0;
        let request_type_len = u32::from_be_bytes(buf[offset..4 + offset].try_into()?) as usize;
        offset += 4;
        if offset + request_type_len - 1 > buf.len() {
            bail!("ReqType: buffer too short to read request_type");
        }
        let req_type = String::from_utf8_lossy(&buf[offset..offset + request_type_len]);
        offset += request_type_len;
        let want_reply = buf[offset] != 0;
        offset += 1;
        Ok(match req_type.as_ref() {
            "exec" => {
                if offset + 4 > buf.len() {
                    bail!("ReqType: buffer too short for exec");
                }
                let command_len = u32::from_be_bytes(buf[offset..4 + offset].try_into()?) as usize;
                offset += 4;
                if offset + command_len > buf.len() {
                    bail!("ReqType: buffer too short for exec");
                }
                RequestType::Exec {
                    want_reply,
                    command: String::from_utf8_lossy(&buf[offset..offset + command_len])
                        .to_string(),
                }
            }
            "exit-status" => {
                if offset + 4 > buf.len() {
                    bail!("ReqType: buffer too short for exit_status");
                }
                let status_code = u32::from_be_bytes(buf[offset..4 + offset].try_into()?);
                RequestType::ExitStatus {
                    want_reply,
                    status_code,
                }
            }
            _ => bail!("Unknown request type: {}", req_type),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SshMsgChannelClose {
    pub recipient_channel: u32,
}

impl SshMsgChannelClose {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != 4 {
            bail!(
                "SshMsgChannelClose: buffer expected size 4, found {}",
                buf.len()
            );
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SshMsgChannelSuccess {
    pub recipient_channel: u32,
}

impl SshMsgChannelSuccess {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != 4 {
            bail!(
                "SshMsgChannelSuccess: buffer expected size 4, found {}",
                buf.len()
            );
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
        })
    }
}

#[derive(Clone)]
pub struct SshMsgChannelData {
    pub recipient_channel: u32,
    pub data: String,
}
impl Debug for SshMsgChannelData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Escape newlines and other control chars
        let pretty_data = self
            .data
            .replace("\\r", "\r")
            .replace("\\n", "\n")
            .replace("\\t", "\t");

        f.debug_struct("SshMsgChannelData")
            .field("recipient_channel", &self.recipient_channel)
            .field("data", &format_args!("\n{}", pretty_data))
            .finish()
    }
}

impl SshMsgChannelData {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            bail!("SshMsgChannelData: buffer too short");
        }
        let data_len = u32::from_be_bytes(buf[4..8].try_into()?) as usize;
        if data_len + 8 > buf.len() {
            bail!("SshMsgChannelData: buffer too short");
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
            data: String::from_utf8_lossy(&buf[8..8 + data_len]).to_string(),
        })
    }
}

/// The window size specifies how many bytes the other party can send
/// before it must wait for the window to be adjusted.  Both parties use
/// the following message to adjust the window.
///
/// byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
/// uint32    recipient channel
/// uint32    bytes to add
///
#[derive(Clone, Debug)]
pub struct SshMsgChannelWindowAdjust {
    pub recipient_channel: u32,
    pub bytes_to_add: u32,
}

impl SshMsgChannelWindowAdjust {
    pub fn new(recipient_channel: u32) -> Self {
        Self {
            recipient_channel,
            bytes_to_add: 32768,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SSHPacketType::SshMsgChannelWindowAdjust as u8);
        buf.extend(self.recipient_channel.to_be_bytes());
        buf.extend(self.bytes_to_add.to_be_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != 8 {
            bail!(
                "SshMsgChannelWindowAdjust: buffer size mismatch, found {}",
                buf.len()
            );
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
            bytes_to_add: u32::from_be_bytes(buf[4..8].try_into()?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SshMsgChannelEof {
    pub recipient_channel: u32,
}

impl SshMsgChannelEof {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != 4 {
            bail!(
                "SshMsgChannelEof: buffer expected size 4, found {}",
                buf.len()
            );
        }
        Ok(Self {
            recipient_channel: u32::from_be_bytes(buf[..4].try_into()?),
        })
    }
}
