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
by file only — never argv, never env vars, never pasted into chat after setup.

```bash
fort --host https://fort.aureuma.ai auth github login --pat-file /path/to/machine.pat
fort --host https://fort.aureuma.ai auth whoami   # agent_id=machine-<name>
```

Login writes a managed session to `~/.fort/session/` (`FORT_SESSION_DIR`
overrides). Later commands need no auth flags; the session refreshes itself.
`--pat-file` must be a `0600` file. The CLI refuses PATs over plaintext HTTP
except to loopback (tests).

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
- After bootstrap, delete PAT files (`shred -u`) — the session + fingerprint
  remain, the credential does not need to sit on disk.
- If a PAT was ever pasted into chat or logs, treat it as exposed: rotate it at
  the source, unenroll, re-enroll.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401 unauthorized` on commands | session expired/revoked | `auth github login` again |
| `401` on login | wrong PAT or not enrolled | check file, ask admin for `auth github list` |
| `429 too many login attempts` | throttle (20 fails/5min/IP) | wait, fix the PAT, retry once |
| `503 github verification unavailable` | GitHub unreachable | retry later; sessions already open keep working |
| `refusing to send ... non-TLS` | http host with PAT | use the https host |
| `secret file permissions` | file looser than 0600 | `chmod 600`, retry |

## Boundaries

- Fort never stores secret values; it authenticates, authorizes (`repo/env/op`),
  and routes to Vault-encrypted `safe` material.
- Cryptography questions are `vault`'s domain; deployment questions are
  `viva`'s. This skill covers operating Fort only.
