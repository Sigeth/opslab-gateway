# opslab-gateway

The access plane of opslab (working name). All student traffic into instances goes through it: browser terminals, web endpoints and the IDE. It holds no database and no secrets. It only trusts short-lived access tokens signed by the [api](https://github.com/Sigeth/opslab-api), whose public keys it fetches from the api's JWKS endpoint.

> Status: M1. Terminals into `pod` machines through Kubernetes exec. SSH terminals (VMs) come in M2, and the web/IDE proxy in M6.

## Endpoints

| Path | What |
|---|---|
| `GET /v1/whoami` | Echoes the verified access token (`Authorization: Bearer …` or `?token=…`) |
| `GET /v1/terminal?token=…` | WebSocket terminal on the machine the token grants. The instance must be `Ready` and belong to the token's user. Binary frames carry the terminal bytes both ways; the browser sends `{"type":"resize","cols":…,"rows":…}` text frames. |
| `GET /readyz` | 200 once the api's keys are loaded, 503 before |
| `GET /healthz` | Liveness |

## Configuration

| Variable | Default | |
|---|---|---|
| `OPSLAB_LISTEN` | `0.0.0.0:8081` | Listen address |
| `OPSLAB_JWKS_URL` | `http://opslab-api:8080/.well-known/jwks.json` | api public keys |
| `OPSLAB_JWKS_REFRESH_SECS` | `300` | Key refresh interval |
| `OPSLAB_TERMINAL_IDLE_SECS` | `1800` | Terminals without input for this long are closed |
| `OPSLAB_LOG_FORMAT` | text | `json` for JSON logs |

## Development

```sh
make lint test
OPSLAB_JWKS_URL=http://localhost:8080/.well-known/jwks.json make run
make image   # linux/amd64 (podman or docker)
```

## Permissions

The gateway reads `ChallengeInstance`s in the instances namespace. The operator binds it the `opslab-gateway-exec` ClusterRole (`pods/exec`) in each instance namespace, so it can exec into machines and nowhere else.

## License

[MIT](LICENSE)
