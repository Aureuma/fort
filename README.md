# fort

`fort` is a lightweight secret broker API and CLI for identity-based access control over secret operations.

## What is included

- `fortd`: HTTP broker service (`/v1/...` API)
- `fort`: CLI for auth, agent/policy admin, secrets operations, and run-time secret injection
- identity-attached policy model at `repo/env/op`
- wildcard bootstrap/admin binding support (`*:*:*`)
- single-image deployment path for SI Viva

## Build

```bash
go build -o .dist/fort ./cmd/fort
go build -o .dist/fortd ./cmd/fortd
```

## Run locally

```bash
export FORT_ADDR=127.0.0.1:8088
export FORT_STATE_PATH=$PWD/fort-state.json
export FORT_JWT_SIGNING_KEY=dev-signing-key
export FORT_BOOTSTRAP_KEY=dev-bootstrap-key

./.dist/fortd
```

In another shell:

```bash
./.dist/fort --host http://127.0.0.1:8088 doctor
```

## Bootstrap workflow (codex profiles)

1. Create admin identity and attach wildcard policy.

```bash
./.dist/fort --host http://127.0.0.1:8088 --bootstrap-key dev-bootstrap-key \
  agent create --id admin --type user

./.dist/fort --host http://127.0.0.1:8088 --bootstrap-key dev-bootstrap-key \
  agent policy set --id admin --bind '*:*:*'
```

2. Issue admin token.

```bash
ADMIN_TOKEN=$(./.dist/fort --json --host http://127.0.0.1:8088 --bootstrap-key dev-bootstrap-key \
  auth issue --agent admin | awk -F'"' '/"token"/{print $4; exit}')
```

3. Create one identity per profile and attach initial wildcard policy.

```bash
./.dist/fort --host http://127.0.0.1:8088 --token "$ADMIN_TOKEN" \
  agent create --id codex-profile-a --type workload

./.dist/fort --host http://127.0.0.1:8088 --token "$ADMIN_TOKEN" \
  agent policy set --id codex-profile-a --bind '*:*:*'
```

4. Issue profile token and use it.

```bash
PROFILE_TOKEN=$(./.dist/fort --json --host http://127.0.0.1:8088 --token "$ADMIN_TOKEN" \
  auth issue --agent codex-profile-a | awk -F'"' '/"token"/{print $4; exit}')

./.dist/fort --host http://127.0.0.1:8088 --token "$PROFILE_TOKEN" \
  set --repo safe --env prod --key API_KEY --value hello

./.dist/fort --host http://127.0.0.1:8088 --token "$PROFILE_TOKEN" \
  get --repo safe --env prod --key API_KEY
```

5. Scope down policies later from wildcard to least-privilege bindings.

## CLI surface

```bash
fort doctor
fort version
fort auth issue|login|whoami|list|revoke
fort auth session open|refresh|close
fort get
fort set
fort list
fort batch-get
fort run
fort agent create|get|list|set-status|rotate|remove
fort agent policy get|set|add|remove|check
```

`fort run` is the only public run command. It internally does `open -> materialize -> close` session calls.

## Container auto-refresh flow

`fort-agent` keeps short-lived access tokens fresh inside each container from a refresh capability.

1. Open a refresh session for the workload identity.

```bash
SESSION_JSON=$(./.dist/fort --json --host http://127.0.0.1:8088 --token "$ADMIN_TOKEN" \
  auth session open --agent codex-profile-a --access-ttl 10m --refresh-ttl 24h)
```

2. Start `fort-agent` in the container with only the refresh token.

```bash
FORT_REFRESH_TOKEN=$(echo "$SESSION_JSON" | awk -F'"' '/"refresh_token"/{print $4; exit}')
docker run --rm \
  --entrypoint /usr/local/bin/fort-agent \
  -e FORT_HOST=http://host.docker.internal:18089 \
  -e FORT_REFRESH_TOKEN="$FORT_REFRESH_TOKEN" \
  -e FORT_TOKEN_PATH=/run/fort/access.token \
  -v /tmp/fort-run:/run/fort \
  aureuma/fort:latest \
  --once
```

3. Application reads the token from the mounted token path and refreshes naturally as `fort-agent` rotates it.

## Deploy with SI Viva (single image)

1. Build image:

```bash
docker build -t aureuma/fort:latest .
```

2. Deploy with Viva:

```bash
viva deploy --file deploy/service.yaml
```

For Traefik-file public routing (`fort.aureuma.com`) on a Viva host with shared Traefik:

```bash
viva deploy --file deploy/service.public.yaml
```

or via SI wrapper (if available in your SI checkout):

```bash
si viva --repo /home/shawn/Development/viva --build deploy --file ./deploy/service.yaml
```

## Test

```bash
go test ./...
./scripts/smoke-container.sh
```
