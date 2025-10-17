# ssh-rs

A Rust SSH client implementation built from scratch.

## ssh-client

A command-line SSH client that implements the SSH protocol with support for:
- ECDH key exchange
- Password authentication  
- AES-GCM encryption
- Channel management and command execution

### Usage

```bash
cargo run --bin ssh-client -- [OPTIONS]
```

**Options:**
- `-s, --server-ip <IP>` - Server IP address (default: 127.0.0.1)
- `-p, --port <PORT>` - Server port (default: 22)
- `-u, --username <USER>` - Username for authentication (default: gautamkumar)

### Example

```bash
cargo run --bin ssh-client -- -s 192.168.1.100 -p 22 -u myuser
```
