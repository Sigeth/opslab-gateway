//! SSH shells on vm machines. The gateway logs in as the student with the
//! instance's key and accepts only the machine's pinned host key, so a
//! machine whose host key changed is refused (fail closed).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use russh::client::{self, Handle, Msg};
use russh::keys::{
    PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, decode_secret_key,
    parse_public_key_base64,
};
use russh::{ChannelMsg, ChannelWriteHalf, Disconnect};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::terminal::{Shell, ShellIo};

/// Bounds the TCP connection, handshake and login.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The keys known_hosts accepts for `host` (a name, port 22).
pub fn host_keys(known_hosts: &str, host: &str) -> Vec<PublicKey> {
    let bracketed = format!("[{host}]:22");
    known_hosts
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let (hosts, _algorithm, key) = (fields.next()?, fields.next()?, fields.next()?);
            hosts
                .split(',')
                .any(|h| h == host || h == bracketed)
                .then(|| parse_public_key_base64(key).ok())
                .flatten()
        })
        .collect()
}

/// Accepts only the pinned host keys.
struct Pinned(Vec<PublicKey>);

impl client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match server {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                self.0.iter().any(|k| k.key_data() == key.key_data())
            }
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

/// Opens a login shell with a PTY on `host`, as `user`.
pub async fn open(
    host: &str,
    port: u16,
    user: &str,
    private_key: &str,
    known_hosts: &str,
) -> anyhow::Result<Shell> {
    let pinned = host_keys(known_hosts, host);
    if pinned.is_empty() {
        bail!("no known host key for {host}");
    }
    let key = decode_secret_key(private_key, None).context("decoding the private key")?;
    let config = Arc::new(client::Config {
        // Idle sessions are ended by the gateway's own timeout.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let login = async {
        let mut handle = client::connect(config, (host, port), Pinned(pinned)).await?;
        let auth = handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
            .await?;
        if !auth.success() {
            bail!("the machine refused the login of {user}");
        }
        Ok::<_, anyhow::Error>(handle)
    };
    let handle = tokio::time::timeout(CONNECT_TIMEOUT, login)
        .await
        .context("timed out connecting")??;

    let channel = handle.channel_open_session().await?;
    channel
        .request_pty(false, "xterm-256color", 80, 24, 0, 0, &[])
        .await?;
    channel.request_shell(false).await?;
    let (mut read, write) = channel.split();

    let (tx, output) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Some(msg) = read.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    if tx.send(data.to_vec()).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
    });
    let stdin = Box::pin(write.make_writer());
    Ok(Shell {
        output,
        io: Box::new(SshIo {
            handle,
            write,
            stdin,
        }),
    })
}

struct SshIo {
    handle: Handle<Pinned>,
    write: ChannelWriteHalf<Msg>,
    stdin: std::pin::Pin<Box<dyn AsyncWrite + Send>>,
}

#[async_trait]
impl ShellIo for SshIo {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stdin.write_all(data).await
    }

    async fn resize(&mut self, cols: u16, rows: u16) {
        let _ = self
            .write
            .window_change(cols.into(), rows.into(), 0, 0)
            .await;
    }

    async fn close(&mut self) {
        let _ = self.write.close().await;
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "terminal closed", "en")
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIIDlZr8q6bUZzRuemEZtrWhvjZOLnIzxNIL09RxHE3mF";

    #[test]
    fn host_keys_by_name() {
        let known = format!(
            "# comment\nbox.inst-a.svc ssh-ed25519 {KEY_A}\nweb.inst-a.svc ssh-ed25519 {KEY_B}\n[db.inst-a.svc]:22 ssh-ed25519 {KEY_B}\n"
        );
        let keys = host_keys(&known, "box.inst-a.svc");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], parse_public_key_base64(KEY_A).unwrap());
        assert_eq!(host_keys(&known, "db.inst-a.svc").len(), 1);
        assert!(host_keys(&known, "inst-a.svc").is_empty());
    }

    #[tokio::test]
    async fn pinned_rejects_other_keys() {
        use client::Handler;
        let a = parse_public_key_base64(KEY_A).unwrap();
        let b = parse_public_key_base64(KEY_B).unwrap();
        let mut pinned = Pinned(vec![a.clone()]);
        let offer = |key: PublicKey| PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: None,
        };
        assert!(pinned.check_server_key(&offer(a)).await.unwrap());
        assert!(!pinned.check_server_key(&offer(b)).await.unwrap());
    }
}
