use crate::ssh::SSHPacketType;
use anyhow::{Result, anyhow, bail};
use std::fmt::Debug;

/// After the key exchange, the client requests a service.  The service
/// is identified by a name. Currently, the following names have been reserved:
/// 1. ssh-userauth
/// 2. ssh-connection

#[derive(Debug, Clone)]
pub enum ServiceRequestType {
    SshUserauth,
    SshConnection,
}

impl ServiceRequestType {
    pub fn to_bytes(&self) -> Vec<u8> {
        let s = self.as_str();

        let mut v = Vec::with_capacity(4 + s.len());
        v.extend((s.len() as u32).to_be_bytes());
        v.extend(s.as_bytes());
        v
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceRequestType::SshUserauth => "ssh-userauth",
            ServiceRequestType::SshConnection => "ssh-connection",
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            bail!("Invalid ssh auth packet");
        }

        // First 4 bytes = length
        let len = u32::from_be_bytes(data[..4].try_into()?) as usize;

        if data.len() < 4 + len {
            bail!("data too short for string length");
        }

        let s = std::str::from_utf8(&data[4..4 + len]).map_err(|_| anyhow!("invalid UTF-8"))?;

        match s {
            "ssh-userauth" => Ok(ServiceRequestType::SshUserauth),
            "ssh-connection" => Ok(ServiceRequestType::SshConnection),
            _ => Err(anyhow!("unknown service request type: {}", s)),
        }
    }
}

/// RFC 4252
/// All authentication requests MUST use the following message format.
/// Only the first few fields are defined; the remaining fields depend on
/// the authentication method.
///
/// byte      SSH_MSG_USERAUTH_REQUEST
/// string    user name in ISO-10646 UTF-8 encoding `[`RFC3629`]`
/// string    service name in US-ASCII
/// string    method name in US-ASCII
/// ....      method specific fields
///
/// All
/// implementations SHOULD support password authentication.
///
/// byte      SSH_MSG_USERAUTH_REQUEST
/// string    user name
/// string    service name
/// string    "password"
/// boolean   FALSE
/// string    plaintext password in ISO-10646 UTF-8 encoding
///
#[derive(Debug, Clone)]
pub struct SshMsgUserAuthRequest {
    pub username: String,
    pub service_name: ServiceRequestType,
    pub method: AuthMethod,
}

impl SshMsgUserAuthRequest {
    pub fn from_user_password(username: &str, password: String) -> Self {
        Self {
            username: username.to_string(),
            service_name: ServiceRequestType::SshConnection,
            method: AuthMethod::Password {
                change_request: false,
                password,
            },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SSHPacketType::SshMsgUserAuthRequest as u8);
        let username_bytes = self.username.as_bytes();
        out.extend((username_bytes.len() as u32).to_be_bytes());
        out.extend(username_bytes);
        let service_name_bytes = self.service_name.as_str().as_bytes();
        out.extend((service_name_bytes.len() as u32).to_be_bytes());
        out.extend(service_name_bytes);
        out.extend(self.method.to_bytes());
        out
    }
}

#[derive(Clone)]
pub enum AuthMethod {
    Password {
        change_request: bool,
        password: String,
    },
}

impl Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password { change_request, .. } => f
                .debug_struct("AuthMethod::Password")
                .field("change_request", change_request)
                .field("password", &"******")
                .finish(),
        }
    }
}

impl AuthMethod {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            AuthMethod::Password {
                change_request,
                password,
            } => {
                let method_name = "password";
                out.extend((method_name.len() as u32).to_be_bytes());
                out.extend(method_name.as_bytes());
                out.push(*change_request as u8);
                let password = password.as_bytes();
                out.extend((password.len() as u32).to_be_bytes());
                out.extend(password);
            }
        }
        out
    }
}
