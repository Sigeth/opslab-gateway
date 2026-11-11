//! Browser terminals: WebSocket ↔ Kubernetes exec into a machine's container.
//!
//! Protocol on the WebSocket:
//! - client → gateway: binary frames are keystrokes (stdin); text frames are
//!   JSON control messages, `{"type":"resize","cols":120,"rows":40}`.
//! - gateway → client: binary frames are terminal output; a final text frame
//!   `{"type":"exit","message":"..."}` explains why the session ended.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{AttachParams, AttachedProcess, TerminalSize};
use kube::{Api, Client};
use opslab_auth::{AccessClaims, AccessKind};
use opslab_types::ChallengeInstance;
use opslab_types::conventions::MACHINE_CONTAINER;
use opslab_types::generated::challengeinstances::{
    ChallengeInstanceStatusMachinesRuntime, ChallengeInstanceStatusPhase,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::app::{Access, AppState};

/// Shell started in the machine: bash when available, as a login shell in
/// the user's home.
const SHELL: &str = "export TERM=xterm-256color; cd \"$HOME\" 2>/dev/null; \
    if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi";

/// Where a terminal opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub namespace: String,
    pub pod: String,
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
}

/// Finds the pod a token grants a terminal on, checking the instance still
/// exists, is ready and belongs to the token's user.
pub fn resolve(
    claims: &AccessClaims,
    instance: Option<&ChallengeInstance>,
) -> Result<Target, Denied> {
    if !matches!(claims.grant.kind, AccessKind::Terminal { .. }) {
        return Err(Denied::NotATerminal);
    }
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
    // Pod and sysbox machines are reached through exec; VMs through SSH (M2).
    let exec = matches!(
        machine.runtime,
        ChallengeInstanceStatusMachinesRuntime::Pod
            | ChallengeInstanceStatusMachinesRuntime::Sysbox
    );
    match (exec, machine.pod.clone(), status.namespace.clone()) {
        (true, Some(pod), Some(namespace)) if machine.ready => Ok(Target { namespace, pod }),
        _ => Err(Denied::NoMachine),
    }
}

/// Opens shells in machines. Faked in tests.
#[async_trait]
pub trait Machines: Send + Sync {
    async fn instance(
        &self,
        namespace: &str,
        name: &str,
    ) -> kube::Result<Option<ChallengeInstance>>;
    async fn shell(&self, target: &Target) -> kube::Result<AttachedProcess>;
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

    async fn shell(&self, target: &Target) -> kube::Result<AttachedProcess> {
        let params = AttachParams::interactive_tty().container(MACHINE_CONTAINER);
        Api::<Pod>::namespaced(self.0.clone(), &target.namespace)
            .exec(&target.pod, ["/bin/sh", "-c", SHELL], &params)
            .await
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
    let mut process = match machines.shell(&target).await {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("cannot open a shell: {e}");
            let _ = ws_tx.send(exit_message(&msg)).await;
            return msg;
        }
    };
    let (Some(mut stdin), Some(mut stdout), Some(resize)) =
        (process.stdin(), process.stdout(), process.terminal_size())
    else {
        return "the shell has no tty".into();
    };

    let output = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => return "the shell exited".to_string(),
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        return "the browser disconnected".into();
                    }
                }
            }
        }
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
                    if stdin.write_all(&data).await.is_err() {
                        return "the shell exited".into();
                    }
                }
                Message::Text(text) => match serde_json::from_str::<Control>(&text) {
                    Ok(Control::Resize { cols, rows }) => {
                        let _ = resize
                            .clone()
                            .send(TerminalSize {
                                width: cols,
                                height: rows,
                            })
                            .await;
                    }
                    Err(_) => tracing::debug!("ignored an unknown control message"),
                },
                _ => {}
            }
        }
    };
    let reason = tokio::select! {
        r = output => r,
        r = input => r,
    };
    process.abort();
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
                {"name": "vm", "runtime": "vm", "ready": true}]}
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
            Target {
                namespace: "inst-hello-1".into(),
                pod: "box".into()
            }
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
                claims("u1", "vm", terminal()),
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
