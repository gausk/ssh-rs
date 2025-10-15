
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
            initial_window_size: 3200,
            maximum_packet_size: 3200,
        }
    }


}

#[derive(Clone, Debug)]
pub enum SshChannelType {
    Session
}

impl SshChannelType {
    pub fn as_str(&self) -> &str {
        match self {
            SshChannelType::Session => "session",
        }
    }
}
