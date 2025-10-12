use serde::{Deserialize, Serialize};

/// After the key exchange, the client requests a service.  The service
/// is identified by a name. Currently, the following names have been reserved:
/// 1. ssh-userauth
/// 2. ssh-connection

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceRequestType {
    SshUserauth,
    SshConnection,
}
