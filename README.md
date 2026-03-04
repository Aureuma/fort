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
fort get
fort set
fort list
fort batch-get
fort run
fort agent create|get|list|set-status|rotate|remove
fort agent policy get|set|add|remove|check
```

`fort run` is the only public run command. It internally does `open -> materialize -> close` session calls.

## Deploy with SI Viva (single image)

1. Build image:

```bash
docker build -t aureuma/fort:latest .
```

2. Deploy with Viva:

```bash
viva deploy --file deploy/service.yaml
```

or via SI wrapper (if available in your SI checkout):

```bash
si viva --repo /home/shawn/Development/viva --build deploy --file ./deploy/service.yaml
```

## Test

```bash
go test ./...
```
