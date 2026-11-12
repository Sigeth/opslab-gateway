//! Browser terminals: WebSocket ↔ a shell on a machine, through Kubernetes
//! exec (pod and sysbox machines) or SSH (vm machines, see [`crate::ssh`]).
//!
//! Protocol on the WebSocket:
//! - client → gateway: binary frames are keystrokes (stdin); text frames are
//!   JSON control messages, `{"type":"resize","cols":120,"rows":40}`.
//! - gateway → client: binary frames are terminal output; a final text frame
//!   `{"type":"exit","message":"..."}` explains why the session ended.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{AttachParams, AttachedProcess, TerminalSize};
use kube::{Api, Client};
use opslab_auth::{AccessClaims, AccessKind};
use opslab_types::ChallengeInstance;
use opslab_types::conventions::{
    MACHINE_CONTAINER, SSH_PORT, SSH_SECRET, SSH_SECRET_KNOWN_HOSTS, SSH_SECRET_STUDENT_KEY,
    STUDENT_USER,
};
use opslab_types::generated::challengeinstances::{
    ChallengeInstanceStatusMachinesRuntime, ChallengeInstanceStatusPhase,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::app::{Access, AppState};

/// Shell started in the machine: bash when available, as a login shell in
/// the user's home.
const SHELL: &str = "export TERM=xterm-256color; cd \"$HOME\" 2>/dev/null; \
    if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi";

/// Where a terminal opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Kubernetes exec into the machine container of a pod.
    Exec { namespace: String, pod: String },
    /// SSH login on a vm machine, with the keys of the instance namespace.
    Ssh {
        namespace: String,
        host: String,
        user: String,
    },
}

/// Why a terminal cannot open.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("this token does not grant a terminal")]
    NotATerminal,
    #[error("the instance does not exist")]
    NoInstance,
    #[error("the instance belongs to someone else")]
    NotOwner,
    #[error("the instance is not ready")]
    NotReady,
    #[error("the machine has no terminal")]
    NoMachine,
    #[error("terminals on virtual machines open as the student only")]
    NotStudent,
}

/// Finds the machine a token grants a terminal on, checking the instance
/// still exists, is ready and belongs to the token's user.
pub fn resolve(
    claims: &AccessClaims,
    instance: Option<&ChallengeInstance>,
) -> Result<Target, Denied> {
    let AccessKind::Terminal { user } = &claims.grant.kind else {
        return Err(Denied::NotATerminal);
    };
    let instance = instance.ok_or(Denied::NoInstance)?;
    if instance.spec.owner.user_id != claims.grant.user_id {
        return Err(Denied::NotOwner);
    }
    let status = instance.status.as_ref().ok_or(Denied::NotReady)?;
    if status.phase != Some(ChallengeInstanceStatusPhase::Ready)
        || instance.metadata.deletion_timestamp.is_some()
    {
        return Err(Denied::NotReady);
    }
    let machine = status
        .machines
        .iter()
        .flatten()
        .find(|m| m.name == claims.grant.machine)
        .ok_or(Denied::NoMachine)?;
    let namespace = status.namespace.clone().ok_or(Denied::NoMachine)?;
    if !machine.ready {
        return Err(Denied::NoMachine);
    }
    match machine.runtime {
        // Through exec, as the container user.
        ChallengeInstanceStatusMachinesRuntime::Pod
        | ChallengeInstanceStatusMachinesRuntime::Sysbox => {
            let pod = machine.pod.clone().ok_or(Denied::NoMachine)?;
            Ok(Target::Exec { namespace, pod })
        }
        // Over SSH: the gateway only holds the student's key.
        ChallengeInstanceStatusMachinesRuntime::Vm => {
            if user != STUDENT_USER {
                return Err(Denied::NotStudent);
            }
            let host = machine.address.clone().ok_or(Denied::NoMachine)?;
            Ok(Target::Ssh {
                namespace,
                host,
                user: user.clone(),
            })
        }
        ChallengeInstanceStatusMachinesRuntime::Vcluster => Err(Denied::NoMachine),
    }
}

/// An interactive shell: its output, and how to feed it.
pub struct Shell {
    /// Terminal output; closed when the shell exits.
    pub output: mpsc::Receiver<Vec<u8>>,
    pub io: Box<dyn ShellIo>,
}

/// Input side of a [`Shell`].
#[async_trait]
pub trait ShellIo: Send {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    async fn resize(&mut self, cols: u16, rows: u16);
    /// Ends the shell.
    async fn close(&mut self);
}

/// Opens shells in machines. Faked in tests.
#[async_trait]
pub trait Machines: Send + Sync {
    async fn instance(
        &self,
        namespace: &str,
        name: &str,
    ) -> kube::Result<Option<ChallengeInstance>>;
    async fn shell(&self, target: &Target) -> anyhow::Result<Shell>;
}

/// The real cluster.
pub struct Kube(pub Client);

#[async_trait]
impl Machines for Kube {
    async fn instance(
        &self,
        namespace: &str,
        name: &str,
    ) -> kube::Result<Option<ChallengeInstance>> {
        Api::<ChallengeInstance>::namespaced(self.0.clone(), namespace)
            .get_opt(name)
            .await
    }

    async fn shell(&self, target: &Target) -> anyhow::Result<Shell> {
        match target {
            Target::Exec { namespace, pod } => {
                let params = AttachParams::interactive_tty().container(MACHINE_CONTAINER);
                let process = Api::<Pod>::namespaced(self.0.clone(), namespace)
                    .exec(pod, ["/bin/sh", "-c", SHELL], &params)
                    .await?;
                exec_shell(process)
            }
            Target::Ssh {
                namespace,
                host,
                user,
            } => {
                let secret = Api::<Secret>::namespaced(self.0.clone(), namespace)
                    .get(SSH_SECRET)
                    .await
                    .context("reading the SSH keys of the instance")?;
                let field = |key: &str| -> anyhow::Result<String> {
                    let data = secret
                        .data
                        .as_ref()
                        .and_then(|d| d.get(key))
                        .with_context(|| format!("{SSH_SECRET} has no {key}"))?;
                    Ok(String::from_utf8(data.0.clone())?)
                };
                crate::ssh::open(
                    host,
                    SSH_PORT,
                    user,
                    &field(SSH_SECRET_STUDENT_KEY)?,
                    &field(SSH_SECRET_KNOWN_HOSTS)?,
                )
                .await
            }
        }
    }
}

/// Wraps a Kubernetes exec session as a [`Shell`].
fn exec_shell(mut process: AttachedProcess) -> anyhow::Result<Shell> {
    let (Some(stdin), Some(mut stdout), Some(resize)) =
        (process.stdin(), process.stdout(), process.terminal_size())
    else {
        anyhow::bail!("the shell has no tty");
    };
    let (tx, output) = mpsc::channel(64);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Ok(Shell {
        output,
        io: Box::new(ExecIo {
            stdin: Box::pin(stdin),
            resize,
            process: Some(process),
        }),
    })
}

struct ExecIo {
    stdin: std::pin::Pin<Box<dyn AsyncWrite + Send>>,
    resize: futures::channel::mpsc::Sender<TerminalSize>,
    process: Option<AttachedProcess>,
}

#[async_trait]
impl ShellIo for ExecIo {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stdin.write_all(data).await
    }

    async fn resize(&mut self, cols: u16, rows: u16) {
        let _ = self
            .resize
            .send(TerminalSize {
                width: cols,
                height: rows,
            })
            .await;
    }

    async fn close(&mut self) {
        if let Some(process) = self.process.take() {
            process.abort();
        }
    }
}

/// Control messages sent by the browser.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Control {
    Resize { cols: u16, rows: u16 },
}

#[derive(Serialize)]
struct Exit<'a> {
    r#type: &'static str,
    message: &'a str,
}

/// GET /v1/terminal?token=… (WebSocket).
pub async fn terminal(
    State(state): State<AppState>,
    Access(claims): Access,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let Some((namespace, name)) = claims.grant.instance.split_once('/') else {
        return (StatusCode::BAD_REQUEST, "invalid instance").into_response();
    };
    let instance = match state.machines.instance(namespace, name).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "reading the instance");
            return (StatusCode::BAD_GATEWAY, "cannot read the instance").into_response();
        }
    };
    let target = match resolve(&claims, instance.as_ref()) {
        Ok(t) => t,
        Err(denied) => {
            tracing::info!(user = claims.grant.user_id, instance = claims.grant.instance, reason = %denied, "terminal denied");
            return (StatusCode::FORBIDDEN, denied.to_string()).into_response();
        }
    };
    // Authorize before upgrading, so denials are plain HTTP errors.
    let ws = match ws {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let machines = state.machines.clone();
    let idle = state.idle_timeout;
    tracing::info!(
        user = claims.grant.user_id,
        instance = claims.grant.instance,
        machine = claims.grant.machine,
        jti = claims.jti,
        "terminal opened"
    );
    ws.on_upgrade(move |socket| async move {
        let reason = session(socket, machines, target, idle).await;
        tracing::info!(
            user = claims.grant.user_id,
            instance = claims.grant.instance,
            reason,
            "terminal closed"
        );
    })
}

/// Pumps bytes both ways until either side stops. Returns why it ended.
async fn session(
    socket: WebSocket,
    machines: Arc<dyn Machines>,
    target: Target,
    idle: Duration,
) -> String {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let Shell { mut output, mut io } = match machines.shell(&target).await {
        Ok(shell) => shell,
        Err(e) => {
            let msg = format!("cannot open a shell: {e:#}");
            let _ = ws_tx.send(exit_message(&msg)).await;
            return msg;
        }
    };

    let reason = {
        let output = async {
            while let Some(chunk) = output.recv().await {
                if ws_tx.send(Message::Binary(chunk.into())).await.is_err() {
                    return "the browser disconnected".to_string();
                }
            }
            "the shell exited".to_string()
        };
        let input = async {
            loop {
                let msg = match tokio::time::timeout(idle, ws_rx.next()).await {
                    Err(_) => return "idle timeout".to_string(),
                    Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => {
                        return "the browser disconnected".into();
                    }
                    Ok(Some(Ok(msg))) => msg,
                };
                match msg {
                    Message::Binary(data) => {
                        if io.write(&data).await.is_err() {
                            return "the shell exited".into();
                        }
                    }
                    Message::Text(text) => match serde_json::from_str::<Control>(&text) {
                        Ok(Control::Resize { cols, rows }) => io.resize(cols, rows).await,
                        Err(_) => tracing::debug!("ignored an unknown control message"),
                    },
                    _ => {}
                }
            }
        };
        tokio::select! {
            r = output => r,
            r = input => r,
        }
    };
    io.close().await;
    reason
}

fn exit_message(message: &str) -> Message {
    Message::Text(
        serde_json::to_string(&Exit {
            r#type: "exit",
            message,
        })
        .unwrap_or_default()
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use opslab_auth::AccessGrant;
    use serde_json::json;

    use super::*;

    fn claims(user: &str, machine: &str, kind: AccessKind) -> AccessClaims {
        AccessClaims {
            iss: "opslab-api".into(),
            aud: "opslab-gateway".into(),
            exp: 0,
            iat: 0,
            jti: "j".into(),
            grant: AccessGrant {
                user_id: user.into(),
                instance: "opslab-instances/hello-1".into(),
                machine: machine.into(),
                kind,
            },
        }
    }

    fn instance(phase: &str) -> ChallengeInstance {
        serde_json::from_value(json!({
            "apiVersion": "opslab.io/v1alpha1", "kind": "ChallengeInstance",
            "metadata": {"name": "hello-1", "namespace": "opslab-instances"},
            "spec": {"challenge": "hello", "owner": {"userID": "u1"}},
            "status": {"phase": phase, "namespace": "inst-hello-1", "machines": [
                {"name": "box", "runtime": "pod", "ready": true, "pod": "box"},
                {"name": "vm", "runtime": "vm", "ready": true, "address": "vm.inst-hello-1.svc"},
                {"name": "booting", "runtime": "vm", "ready": false, "address": "booting.inst-hello-1.svc"}]}
        }))
        .unwrap()
    }

    fn terminal() -> AccessKind {
        AccessKind::Terminal {
            user: "student".into(),
        }
    }

    #[test]
    fn resolves_the_pod_of_a_ready_machine() {
        let target = resolve(&claims("u1", "box", terminal()), Some(&instance("Ready"))).unwrap();
        assert_eq!(
            target,
            Target::Exec {
                namespace: "inst-hello-1".into(),
                pod: "box".into()
            }
        );
    }

    #[test]
    fn resolves_a_vm_to_ssh_as_the_student() {
        let target = resolve(&claims("u1", "vm", terminal()), Some(&instance("Ready"))).unwrap();
        assert_eq!(
            target,
            Target::Ssh {
                namespace: "inst-hello-1".into(),
                host: "vm.inst-hello-1.svc".into(),
                user: "student".into()
            }
        );
        let root = AccessKind::Terminal {
            user: "root".into(),
        };
        assert_eq!(
            resolve(&claims("u1", "vm", root), Some(&instance("Ready"))),
            Err(Denied::NotStudent)
        );
    }

    #[test]
    fn denies_everything_else() {
        let ready = instance("Ready");
        let cases = [
            (
                claims("u1", "box", AccessKind::Ide),
                Some(&ready),
                Denied::NotATerminal,
            ),
            (claims("u1", "box", terminal()), None, Denied::NoInstance),
            (
                claims("u2", "box", terminal()),
                Some(&ready),
                Denied::NotOwner,
            ),
            (
                claims("u1", "nope", terminal()),
                Some(&ready),
                Denied::NoMachine,
            ),
            (
                claims("u1", "booting", terminal()),
                Some(&ready),
                Denied::NoMachine,
            ),
        ];
        for (claims, instance, want) in cases {
            assert_eq!(resolve(&claims, instance), Err(want));
        }
        let provisioning = instance("Provisioning");
        assert_eq!(
            resolve(&claims("u1", "box", terminal()), Some(&provisioning)),
            Err(Denied::NotReady)
        );
    }

    #[test]
    fn control_messages() {
        let c: Control = serde_json::from_str(r#"{"type":"resize","cols":120,"rows":40}"#).unwrap();
        assert_eq!(
            c,
            Control::Resize {
                cols: 120,
                rows: 40
            }
        );
        assert!(serde_json::from_str::<Control>(r#"{"type":"paste"}"#).is_err());
    }
}
