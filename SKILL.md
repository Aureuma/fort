# Fort Skill — secret access for agents

Use this skill whenever you need to read or write secrets. Fort is the only
door to secret material: never read `safe` files directly, never use the
`vault` CLI for secret values, never bypass Fort.

## Setup

- Binary: `fort` (needs version 1.0.3+ for GitHub login; check with `fort version`).
- Host (first match wins): `--host`, `FORT_HOST`, `~/.fort/settings.toml` (`[fort].host`).
- Production host: `https://fort.aureuma.ai`. Always HTTPS outside tests.

## Authenticate (GitHub PAT)

Each machine has its own fine-grained PAT enrolled by fingerprint. PATs travel
by file or interactive prompt only — never argv, never env vars, never pasted
into chat after setup.

```bash
fort --host https://fort.aureuma.ai auth github login   # prompts once (1.0.7+), stores PAT, reuses it later
fort --host https://fort.aureuma.ai auth github login --pat-file /path/to/machine.pat   # explicit file, never stored
fort --host https://fort.aureuma.ai auth whoami   # agent_id=machine-<name>
```

Login writes a managed session to `~/.fort/session/` (`FORT_SESSION_DIR`
overrides). Later commands need no auth flags; the session refreshes itself.
Without `--pat-file`, the entered PAT is stored at `~/.fort/github.pat`
(`0600`) after a successful login and reused by later logins; delete it to
enter a different PAT. `--pat-file` must be a `0600` file. The CLI refuses
PATs over plaintext HTTP except to loopback (tests).

```bash
fort --host https://fort.aureuma.ai auth github logout   # closes session, removes files
```

## Daily commands

```bash
fort get --repo <repo> --env <dev|prod> --key <KEY> [--format raw]
fort set --repo <repo> --env <dev|prod> --key <KEY> --value-file /path/to/0600-file
fort list --repo <repo> --env <dev|prod> [--prefix PREFIX]
fort batch-get --repo <repo> --env <dev|prod> --keys K1,K2
fort run --repo <repo> --env <dev|prod> --keys K1,K2 -- <command...>   # secrets only in child env
fort scope ensure --repo <repo> --env <env>                            # admin: new encryption scope
```

Rules:

- `set` takes `--value-file` (a `0600` file) for anything sensitive. `--value`
  leaks into the process list — fixtures only.
- `get` prints the secret. Pipe to the consumer or a file; do not echo values
  into logs, chat, or committed files.
- `run` materializes secrets only for the child process lifetime. Prefer it
  over `get` when a command needs credentials.

## Token rotation (npm)

```bash
fort rotate npm --repo <repo> --env <dev|prod> --token-key <KEY> \
  --management-token-key <MGMT_KEY> [--password-key <PWD_KEY>] \
  --otp-file /path/to/0600-otp --name <token-name> \
  --package <pkg> | --scope <scope> | --org <org> | --all-packages \
  [--revoke-old] [--dry-run] \
  [--github-actions-repo Owner/repo --github-secret-name NPM_TOKEN \
   --github-token-key <GH_KEY> [--github-token-repo <r> --github-token-env <e>]]
```

Rules:

- Every npm input resolves through Fort: the publish token, the management
  token, and the npm password key. Omit `--password-key` only when the
  management credential accepts passwordless token creation.
- `--otp-file` must be a `0600` file holding the current npm OTP. Use
  `--revoke-otp-file` when revocation needs a fresher code than creation.
- Run `--dry-run` first: it validates the command shape and sinks without
  loading secret values.
- Rotation order is create → store in Fort → update GitHub Actions secrets
  → revoke old. The old token is revoked only after every configured sink
  succeeds, so after a failed sink fix the sink and re-run instead of
  revoking by hand.
- Output never prints token values (JSON shows a redacted fingerprint only).

## Provider credentials (fort keys)

All key lifecycle lives under one command: `fort keys <verb> <provider>`.
Today the provider is `r2` (plus `npm` under `rotate`). The old
`fort r2 ...` and `fort rotate ...` spellings still work but print a
deprecation pointer; they go away in the next minor.

```bash
fort keys issue r2 --bucket <name> --permission object-read-only \
  --ttl-seconds 3600 --parent-repo <repo> --parent-env <dev|prod> \
  --parent-key <KEY> [--dry-run]
fort keys create r2 --name <token> --bucket <b> [--bucket <b2>] \
  --account-id <id> --repo <r> --env <e> --id-key <K> --secret-key <S> \
  [--dry-run]
fort keys rotate r2 --repo <r> --env <e> --id-key <K> --secret-key <S> \
  --account-id <id> [--token-id <id>] [--revoke-old] [--dry-run]
fort keys revoke r2 --token-id <id> --account-id <id> [--dry-run]
fort keys list r2 --account-id <id>
fort keys audit r2 --account-id <id> --check <repo/env/key> [...]
```

Rules:

- `issue` mints short-lived temp creds server-side; the caller needs
  `get` on both the issuer scope and the parent-key scope. TTL caps at
  604800 (7 days). Credentials print as `key=value` lines on stdout.
- `create`, `rotate`, `revoke`, `list`, and `audit` run client-side
  against Cloudflare with a manager token that defaults to
  `fort/prod` `CF_R2_TOKEN_MANAGER` (override with `--manager-repo`,
  `--manager-env`, `--manager-key`). That token needs Account API
  Tokens Read+Write and is the one human-bootstrapped credential.
- `create` stores the S3 pair in Fort and S3-verifies every bucket
  before reporting success. `rotate` copies the live token policy,
  cuts Fort over, verifies, then deletes the old token only with
  `--revoke-old` (a missing old token reports `already_absent`).
- Run `--dry-run` first: create/rotate/revoke validate shape without
  loading secrets or calling Cloudflare.
- `list` prints live token ids, names, and policies (never values).
  `audit` matches them against `--check repo/env/key` entries and
  reports `UNMATCHED` tokens and `ORPHAN_CHECK` keys.
- Target scopes must exist (`fort scope ensure`, admin) before
  `create` stores into them.

## Admin commands (admin token required)

```bash
fort agent create --id <id> --type workload|user|ci
fort agent policy set --id <id> --bind '<repo>:<env>:<op,...>'   # repeatable; '*:*:*' = full
fort agent policy check --id <id> --repo <r> --env <e> --op <op>
fort agent list|get|set-status|rotate|remove --id <id>
fort auth github enroll --agent <id> --pat-file /path/to/0600.pat
fort auth github list                       # fingerprint prefixes, never PATs
fort auth github unenroll --agent <id>      # revokes that machine's login
```

Enroll validates the PAT live against GitHub before storing its fingerprint.
Unenroll is the revocation path for a lost machine or rotated PAT (then enroll
the replacement). One fingerprint per agent; re-enroll replaces.

## Secrets discipline (non-negotiable)

- Secret files are regular files at `0600` or stricter. Fort refuses looser ones.
- Never commit secrets or PATs. Never print them. `grep`-check before committing
  near secrets.
- After bootstrap, delete operator-supplied PAT files (`shred -u`). The
  CLI-managed `~/.fort/github.pat` remains for re-login; remove it as well on
  fully decommissioned machines (server-side revocation is `unenroll`).
- If a PAT was ever pasted into chat or logs, treat it as exposed: rotate it at
  the source, unenroll, re-enroll.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401 unauthorized` on commands | session expired/revoked | `auth github login` again |
| `401` on login | wrong PAT or not enrolled | check file (or delete `~/.fort/github.pat` to re-enter), ask admin for `auth github list` |
| `429 too many login attempts` | throttle (20 fails/5min/IP) | wait, fix the PAT, retry once |
| `503 github verification unavailable` | GitHub unreachable | retry later; sessions already open keep working |
| `refusing to send ... non-TLS` | http host with PAT | use the https host |
| `secret file permissions` | file looser than 0600 | `chmod 600`, retry |

## Boundaries

- Fort never stores secret values; it authenticates, authorizes (`repo/env/op`),
  and routes to Vault-encrypted `safe` material.
- Cryptography questions are `vault`'s domain; deployment questions are
  `viva`'s. This skill covers operating Fort only.
