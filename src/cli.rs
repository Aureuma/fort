use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Args, Parser, Subcommand};
use crypto_box::{
    PublicKey as CryptoBoxPublicKey, SalsaBox, SecretKey as CryptoBoxSecretKey,
    aead::{Aead, generic_array::GenericArray, rand_core::OsRng},
};
use reqwest::Method;
use reqwest::blocking::Client as HttpClient;
use serde_json::{Value, json};
use url::Url;

use crate::hostcfg::host_from_settings;
use crate::model::{Binding, Operation};

#[derive(Parser)]
#[command(
    name = "fort",
    about = "Policy and authentication API for Vault secret operations",
    long_about = "Fort is the only door to secret material: it authenticates, authorizes repo/env/op access, and routes secret operations to Vault-encrypted safe data.\n\nHost resolution (first match wins): --host, FORT_HOST, ~/.fort/settings.toml [fort].host.\nAuthentication: --token-file, else the managed session in $FORT_SESSION_DIR (default ~/.fort/session/). See `fort auth github login` to start a session."
)]
pub struct FortCli {
    #[arg(long, help = "Fort server base URL (https outside tests)")]
    host: Option<String>,
    #[arg(
        long,
        help = "0600 file holding a bearer token (else use the managed session)"
    )]
    token_file: Option<String>,
    #[arg(long, help = "Print machine-readable JSON instead of text")]
    json: bool,
    #[command(subcommand)]
    command: FortCommand,
}

#[derive(Subcommand)]
enum FortCommand {
    #[command(about = "Print the CLI version (no server contact)")]
    Version,
    #[command(about = "Check server health, readiness, and current auth")]
    Doctor,
    #[command(about = "Issue, inspect, and revoke tokens and sessions")]
    Auth(AuthCommand),
    #[command(about = "Print one secret value")]
    Get(GetArgs),
    #[command(about = "Write one secret value")]
    Set(SetArgs),
    #[command(about = "List secret key names (never values)")]
    List(ListArgs),
    #[command(name = "batch-get", about = "Print several secret values at once")]
    BatchGet(BatchGetArgs),
    #[command(about = "Manage secret scopes (admin)")]
    Scope(ScopeCommand),
    #[command(about = "Run a child command with secrets materialized")]
    Run(RunArgs),
    #[command(about = "Rotate third-party provider credentials")]
    Rotate(Box<RotateCommand>),
    #[command(about = "Manage agents and policies (admin)")]
    Agent(AgentCommand),
}

#[derive(Args)]
struct GetArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Secret key name")]
    key: String,
    #[arg(long, default_value = "raw", help = "Output format: raw or json")]
    format: String,
}

#[derive(Args)]
struct SetArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Secret key name")]
    key: String,
    #[arg(
        long,
        conflicts_with = "value_file",
        help = "Secret value on argv (fixtures only; leaks into the process list)"
    )]
    value: Option<String>,
    #[arg(
        long,
        conflicts_with = "value",
        help = "0600 file holding the secret value (use for anything sensitive)"
    )]
    value_file: Option<String>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Compare-and-swap guard (reserved; the server does not enforce it yet)"
    )]
    cas_version: i64,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(
        long,
        default_value = "",
        help = "Only list keys starting with this prefix"
    )]
    prefix: String,
}

#[derive(Args)]
struct BatchGetArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Comma-separated secret key names")]
    keys: String,
}

#[derive(Args)]
struct ScopeCommand {
    #[command(subcommand)]
    command: ScopeSubcommand,
}

#[derive(Subcommand)]
enum ScopeSubcommand {
    #[command(about = "Create a repo/env encryption scope if missing (admin)")]
    Ensure(ScopeEnsureArgs),
}

#[derive(Args)]
struct ScopeEnsureArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
}

#[derive(Args)]
#[command(about = "Run a child command with secrets materialized for its lifetime only")]
struct RunArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Comma-separated secret key names")]
    keys: String,
    #[arg(
        long,
        default_value = "files",
        help = "Delivery mode: files (0600 temp files) or env"
    )]
    mode: String,
    #[arg(long, default_value = "60s", help = "Run session lifetime, e.g. 60s")]
    ttl: String,
    #[arg(last = true, required = true, help = "Child command after --")]
    command: Vec<String>,
}

#[derive(Args)]
struct RotateCommand {
    #[command(subcommand)]
    command: RotateSubcommand,
}

#[derive(Subcommand)]
enum RotateSubcommand {
    #[command(about = "Rotate an npm granular access token through Fort")]
    Npm(Box<NpmRotateArgs>),
}

#[derive(Args)]
#[command(
    about = "Rotate an npm granular access token through Fort",
    long_about = "Create a new npm granular access token, store it back through Fort, sync configured GitHub Actions secrets, then revoke the old token only after every sink succeeds. All npm inputs resolve through Fort; the OTP always comes from a 0600 file. Run --dry-run first: it validates shape and sinks without loading secret values."
)]
struct NpmRotateArgs {
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Fort key holding the npm publish token to replace")]
    token_key: String,
    #[arg(
        long,
        help = "Fort key holding the npm token-management bearer (defaults to --token-key)"
    )]
    management_token_key: Option<String>,
    #[arg(
        long,
        help = "Fort key holding the npm password (omit only for passwordless-capable credentials)"
    )]
    password_key: Option<String>,
    #[arg(
        long,
        help = "0600 file holding the current npm OTP (required unless --dry-run)"
    )]
    otp_file: Option<String>,
    #[arg(
        long,
        help = "0600 file holding a fresher OTP for revocation (defaults to --otp-file)"
    )]
    revoke_otp_file: Option<String>,
    #[arg(long, help = "Name for the new npm token")]
    name: String,
    #[arg(long, default_value = "", help = "Description for the new npm token")]
    description: String,
    #[arg(
        long,
        default_value_t = 90,
        help = "New token lifetime in days (read-write capped at 90)"
    )]
    expires_days: i64,
    #[arg(
        long = "package",
        help = "Repeatable: package the token may publish, e.g. @org/pkg"
    )]
    packages: Vec<String>,
    #[arg(long = "scope", help = "Repeatable: scope the token may publish")]
    scopes: Vec<String>,
    #[arg(long = "org", help = "Repeatable: org the token may manage")]
    orgs: Vec<String>,
    #[arg(long = "cidr", help = "Repeatable: CIDR the token is restricted to")]
    cidr: Vec<String>,
    #[arg(
        long,
        default_value = "read-write",
        help = "Packages/scopes permission: read-only, read-write, or no-access"
    )]
    packages_permission: String,
    #[arg(
        long,
        default_value = "no-access",
        help = "Orgs permission: read-only, read-write, or no-access"
    )]
    orgs_permission: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Grant all packages instead of explicit --package values"
    )]
    all_packages: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Set npm bypass_2fa on the new token"
    )]
    bypass_2fa: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Revoke the old npm token after every sink succeeds"
    )]
    revoke_old: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Validate shape and sinks without loading secret values"
    )]
    dry_run: bool,
    #[arg(
        long,
        default_value = "https://registry.npmjs.org",
        help = "npm registry base URL"
    )]
    registry: String,
    #[arg(
        long = "github-actions-repo",
        help = "Repeatable Owner/repo to sync the new token into"
    )]
    github_actions_repos: Vec<String>,
    #[arg(
        long,
        default_value = "",
        help = "Actions secret name to update (required with --github-actions-repo)"
    )]
    github_secret_name: String,
    #[arg(
        long,
        help = "Fort key holding the GitHub token (required with --github-actions-repo)"
    )]
    github_token_key: Option<String>,
    #[arg(long, help = "Fort repo holding the GitHub token (defaults to --repo)")]
    github_token_repo: Option<String>,
    #[arg(long, help = "Fort env holding the GitHub token (defaults to --env)")]
    github_token_env: Option<String>,
    #[arg(
        long,
        default_value = "https://api.github.com",
        help = "GitHub API base URL"
    )]
    github_api_base: String,
}

#[derive(Args)]
struct AuthCommand {
    #[command(subcommand)]
    command: AuthSubcommand,
}

#[derive(Subcommand)]
enum AuthSubcommand {
    #[command(about = "Mint an access token for an agent (admin)")]
    Issue(AuthIssueArgs),
    #[command(about = "Alias of issue (admin)")]
    Login(AuthIssueArgs),
    #[command(about = "Show the identity behind the current token")]
    Whoami,
    #[command(about = "List issued tokens (admin)")]
    List(AuthListArgs),
    #[command(about = "Revoke a token by id (admin)")]
    Revoke(AuthRevokeArgs),
    #[command(about = "Open, refresh, and close refresh sessions")]
    Session(AuthSessionCommand),
    #[command(about = "Machine login with GitHub PATs")]
    Github(AuthGithubCommand),
}

#[derive(Args)]
struct AuthIssueArgs {
    #[arg(long, help = "Agent id to mint the token for")]
    agent: String,
    #[arg(
        long,
        default_value = "",
        help = "Token lifetime, e.g. 15m (empty means server default)"
    )]
    ttl: String,
    #[arg(long, default_value = "fort-api", help = "Token audience claim")]
    aud: String,
}

#[derive(Args)]
struct AuthListArgs {
    #[arg(long, default_value = "", help = "Only list tokens for this agent id")]
    agent: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Hide revoked and expired tokens"
    )]
    active_only: bool,
}

#[derive(Args)]
struct AuthRevokeArgs {
    #[arg(long, help = "Token id (jti) to revoke")]
    jti: String,
    #[arg(long, default_value = "", help = "Audit reason for the revocation")]
    reason: String,
}

#[derive(Args)]
struct AuthSessionCommand {
    #[command(subcommand)]
    command: AuthSessionSubcommand,
}

#[derive(Subcommand)]
enum AuthSessionSubcommand {
    #[command(about = "Open a refresh session for workload runtimes (admin)")]
    Open(AuthSessionOpenArgs),
    #[command(about = "Rotate a refresh token (managed tokens refresh in place)")]
    Refresh(AuthSessionRefreshArgs),
    #[command(about = "Close a refresh session")]
    Close(AuthSessionCloseArgs),
}

#[derive(Args)]
struct AuthSessionOpenArgs {
    #[arg(long, help = "Agent id to open the session for")]
    agent: String,
    #[arg(long, default_value = "fort-api", help = "Token audience claim")]
    aud: String,
    #[arg(
        long,
        default_value = "",
        help = "Access token lifetime, e.g. 3m (empty means server default)"
    )]
    access_ttl: String,
    #[arg(
        long,
        default_value = "",
        help = "Refresh session lifetime, e.g. 30m (empty means server default)"
    )]
    refresh_ttl: String,
    #[arg(long, help = "0600 path the new refresh token is written to")]
    refresh_token_out: String,
}

#[derive(Args)]
struct AuthSessionRefreshArgs {
    #[arg(long, help = "0600 file holding the current refresh token")]
    refresh_token_file: String,
    #[arg(
        long,
        help = "0600 path for the rotated token (defaults to refreshing in place)"
    )]
    refresh_token_out: Option<String>,
}

#[derive(Args)]
struct AuthSessionCloseArgs {
    #[arg(long, default_value = "", help = "Session id to close")]
    session_id: String,
    #[arg(
        long,
        help = "0600 file holding the session refresh token (sent with the close)"
    )]
    refresh_token_file: Option<String>,
}

#[derive(Args)]
struct AuthGithubCommand {
    #[command(subcommand)]
    command: AuthGithubSubcommand,
}

#[derive(Subcommand)]
enum AuthGithubSubcommand {
    #[command(about = "Log this machine in with its GitHub PAT (prompt or file)")]
    Login(AuthGithubLoginArgs),
    #[command(about = "Close the managed session and remove session files")]
    Logout,
    #[command(about = "Enroll a machine PAT fingerprint for an agent (admin)")]
    Enroll(AuthGithubEnrollArgs),
    #[command(about = "Revoke a machine login for an agent (admin)")]
    Unenroll(AuthGithubUnenrollArgs),
    #[command(about = "List enrolled PAT fingerprints, never PATs (admin)")]
    List,
}

#[derive(Args)]
struct AuthGithubLoginArgs {
    #[arg(
        long,
        help = "0600 file holding the machine PAT (else prompt once and reuse the stored PAT)"
    )]
    pat_file: Option<String>,
    #[arg(long, default_value = "fort-api", help = "Token audience claim")]
    aud: String,
    #[arg(
        long,
        default_value = "",
        help = "Access token lifetime, e.g. 3m (empty means server default)"
    )]
    access_ttl: String,
    #[arg(
        long,
        default_value = "",
        help = "Refresh session lifetime, e.g. 30d (empty means server default)"
    )]
    refresh_ttl: String,
}

#[derive(Args)]
struct AuthGithubEnrollArgs {
    #[arg(long, help = "Agent id to bind the PAT fingerprint to")]
    agent: String,
    #[arg(
        long,
        help = "0600 file holding the PAT to validate live and enroll by fingerprint"
    )]
    pat_file: String,
}

#[derive(Args)]
struct AuthGithubUnenrollArgs {
    #[arg(long, help = "Agent id whose machine login is revoked")]
    agent: String,
}

#[derive(Args)]
struct AgentCommand {
    #[command(subcommand)]
    command: AgentSubcommand,
}

#[derive(Subcommand)]
enum AgentSubcommand {
    #[command(about = "Create an agent (admin)")]
    Create(AgentCreateArgs),
    #[command(about = "Show one agent (admin)")]
    Get(AgentGetArgs),
    #[command(about = "List agents (admin)")]
    List(AgentListArgs),
    #[command(about = "Activate or disable an agent (admin)")]
    SetStatus(AgentSetStatusArgs),
    #[command(about = "Rotate agent credentials, invalidating old tokens and sessions (admin)")]
    Rotate(AgentRotateArgs),
    #[command(about = "Remove an agent (admin)")]
    Remove(AgentRemoveArgs),
    #[command(about = "Manage agent policy bindings (admin)")]
    Policy(AgentPolicyCommand),
}

#[derive(Args)]
struct AgentCreateArgs {
    #[arg(long, help = "Agent id to create")]
    id: String,
    #[arg(
        long = "type",
        default_value = "workload",
        help = "Agent type: workload, user, or ci"
    )]
    agent_type: String,
    #[arg(
        long,
        default_value = "active",
        help = "Initial status: active or disabled"
    )]
    status: String,
}

#[derive(Args)]
struct AgentGetArgs {
    #[arg(long, help = "Agent id")]
    id: String,
}

#[derive(Args)]
struct AgentListArgs {
    #[arg(
        long = "type",
        help = "Only list this agent type: workload, user, or ci"
    )]
    agent_type: Option<String>,
    #[arg(long, help = "Only list this status: active or disabled")]
    status: Option<String>,
}

#[derive(Args)]
struct AgentSetStatusArgs {
    #[arg(long, help = "Agent id")]
    id: String,
    #[arg(long, help = "New status: active or disabled")]
    status: String,
}

#[derive(Args)]
struct AgentRotateArgs {
    #[arg(long, help = "Agent id whose credentials are rotated")]
    id: String,
}

#[derive(Args)]
struct AgentRemoveArgs {
    #[arg(long, help = "Agent id to remove")]
    id: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Force removal (reserved; removal never prompts today)"
    )]
    force: bool,
}

#[derive(Args)]
struct AgentPolicyCommand {
    #[command(subcommand)]
    command: AgentPolicySubcommand,
}

#[derive(Subcommand)]
enum AgentPolicySubcommand {
    #[command(about = "Show an agent policy (admin)")]
    Get(AgentGetArgs),
    #[command(about = "Replace an agent policy with new bindings (admin)")]
    Set(AgentPolicySetArgs),
    #[command(about = "Add one binding to an agent policy (admin)")]
    Add(AgentPolicyAddRemoveArgs),
    #[command(about = "Remove one binding from an agent policy (admin)")]
    Remove(AgentPolicyAddRemoveArgs),
    #[command(about = "Check whether an agent may perform an operation (admin)")]
    Check(AgentPolicyCheckArgs),
}

#[derive(Args)]
struct AgentPolicySetArgs {
    #[arg(long, help = "Agent id")]
    id: String,
    #[arg(
        long = "bind",
        required = true,
        help = "Repeatable binding <repo|*>:<env|*>:<ops|*> with ops from get,set,run,list,batch-get ('*:*:*' is full access)"
    )]
    binds: Vec<String>,
    #[arg(
        long,
        default_value_t = true,
        help = "Replace the whole policy (reserved; set always replaces today)"
    )]
    replace: bool,
}

#[derive(Args)]
struct AgentPolicyAddRemoveArgs {
    #[arg(long, help = "Agent id")]
    id: String,
    #[arg(
        long,
        help = "Binding <repo|*>:<env|*>:<ops|*> with ops from get,set,run,list,batch-get"
    )]
    bind: String,
}

#[derive(Args)]
struct AgentPolicyCheckArgs {
    #[arg(long, help = "Agent id")]
    id: String,
    #[arg(long, help = "Policy repository scope, e.g. aureuma")]
    repo: String,
    #[arg(long, help = "Environment scope, e.g. dev or prod")]
    env: String,
    #[arg(long, help = "Operation to check: get, set, run, list, or batch-get")]
    op: String,
}

pub fn run() -> Result<()> {
    crate::sigpipe::restore_default();
    reject_deprecated_token_value_env()?;
    let cli = FortCli::parse();
    if matches!(cli.command, FortCommand::Version) {
        return cmd_version(cli.json);
    }
    let mut client = Client::new(cli.host, cli.token_file, cli.json)?;
    client.ensure_fresh_managed_token()?;
    client.run(cli.command)
}

fn cmd_version(json: bool) -> Result<()> {
    if json {
        print_json(&json!({ "version": env!("CARGO_PKG_VERSION") }))
    } else {
        println!("{}", env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}

struct Client {
    host: String,
    token: String,
    managed: bool,
    json: bool,
    http: HttpClient,
}

impl Client {
    fn new(host: Option<String>, token_file: Option<String>, json: bool) -> Result<Self> {
        let host = resolve_host(host)?;
        let resolved = resolve_token(token_file)?;
        Ok(Self {
            host,
            token: resolved.token,
            managed: resolved.managed,
            json,
            http: HttpClient::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build http client")?,
        })
    }

    /// Managed session support: when no explicit token source is in play and a
    /// `$FORT_SESSION_DIR/refresh.token` (default `~/.fort/session/refresh.token`)
    /// session exists, bootstrap or refresh the access token in place so plain
    /// `fort get ...` works inside managed runtimes with no extra flags.
    fn ensure_fresh_managed_token(&mut self) -> Result<()> {
        if !self.token.trim().is_empty() && !self.managed {
            return Ok(());
        }
        let Some(refresh_path) = managed_refresh_token_path() else {
            return Ok(());
        };
        if !Path::new(&refresh_path).exists() {
            return Ok(());
        }
        if !self.token.trim().is_empty() && !token_needs_refresh(&self.token) {
            return Ok(());
        }
        let refresh_token =
            read_secret_file(&refresh_path).context("read managed refresh token")?;
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/auth/session/refresh",
            Some(json!({ "refresh_token": refresh_token })),
            false,
        )?;
        ensure_status(status, 200, &response).context("refresh managed session")?;
        let access_token = response["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let next_refresh_token = response["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if access_token.trim().is_empty() || next_refresh_token.trim().is_empty() {
            bail!("managed session refresh response missing tokens");
        }
        let access_path = managed_access_token_path().unwrap_or_default();
        write_secret_file(&access_path, &access_token)?;
        write_secret_file(&refresh_path, &next_refresh_token)?;
        self.token = access_token;
        self.managed = true;
        Ok(())
    }

    fn run(&self, command: FortCommand) -> Result<()> {
        match command {
            FortCommand::Version => cmd_version(self.json),
            FortCommand::Doctor => self.cmd_doctor(),
            FortCommand::Auth(command) => self.cmd_auth(command.command),
            FortCommand::Get(args) => self.cmd_get(args),
            FortCommand::Set(args) => self.cmd_set(args),
            FortCommand::List(args) => self.cmd_list(args),
            FortCommand::BatchGet(args) => self.cmd_batch_get(args),
            FortCommand::Scope(command) => self.cmd_scope(command.command),
            FortCommand::Run(args) => self.cmd_run(args),
            FortCommand::Rotate(command) => self.cmd_rotate(command.command),
            FortCommand::Agent(command) => self.cmd_agent(command.command),
        }
    }

    fn api_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        use_token: bool,
    ) -> Result<(u16, Value)> {
        let url = format!("{}{}", self.host, path);
        let mut request = self.http.request(method, url);
        if use_token {
            if self.token.trim().is_empty() {
                bail!("token file auth required");
            }
            request = request.bearer_auth(self.token.trim());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().context("send api request")?;
        let status = response.status().as_u16();
        let json = response.json::<Value>().unwrap_or_else(|_| json!({}));
        Ok((status, json))
    }

    fn cmd_doctor(&self) -> Result<()> {
        let (health_status, health) = self.api_request(Method::GET, "/v1/health", None, false)?;
        let (ready_status, ready) = self.api_request(Method::GET, "/v1/ready", None, false)?;
        let mut auth_error = None;
        let mut out = json!({
            "host": self.host,
            "health_status": health_status,
            "health": health,
            "ready_status": ready_status,
            "ready": ready
        });
        if !self.token.is_empty() {
            match self.api_request(Method::GET, "/v1/auth/whoami", None, true) {
                Ok((status, whoami)) => {
                    out["whoami_status"] = json!(status);
                    out["whoami"] = whoami;
                    if status != 200 {
                        auth_error = Some(anyhow!("fort auth check failed with status {status}"));
                    }
                }
                Err(error) => {
                    let detail = error.to_string();
                    out["whoami_error"] = json!(detail);
                    auth_error = Some(error.context("fort auth check failed"));
                }
            }
        }
        if self.json {
            print_json(&out)?;
        } else {
            println!("host: {}", self.host);
            println!("health: {}", health_status);
            println!("ready: {}", ready_status);
            if let Some(status) = out.get("whoami_status").and_then(Value::as_u64) {
                if status == 200 {
                    println!("auth: ok ({})", out["whoami"]);
                } else {
                    println!("auth: failed status={} ({})", status, out["whoami"]);
                }
            } else if out.get("whoami_error").is_some() {
                println!("auth: failed ({})", out["whoami_error"]);
            }
        }
        if let Some(error) = auth_error {
            return Err(error);
        }
        Ok(())
    }

    fn cmd_auth(&self, command: AuthSubcommand) -> Result<()> {
        match command {
            AuthSubcommand::Issue(args) | AuthSubcommand::Login(args) => {
                self.require_admin_token()?;
                let mut body = json!({
                    "agent_id": args.agent.trim(),
                    "aud": args.aud.trim(),
                });
                if !args.ttl.trim().is_empty() {
                    body["ttl"] = json!(args.ttl.trim());
                }
                let (status, response) =
                    self.api_request(Method::POST, "/v1/auth/token", Some(body), true)?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!("{}", response["token"].as_str().unwrap_or_default());
                    Ok(())
                }
            }
            AuthSubcommand::Whoami => {
                let (status, response) =
                    self.api_request(Method::GET, "/v1/auth/whoami", None, true)?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "agent_id={} token_jti={}",
                        response["agent"]["id"].as_str().unwrap_or_default(),
                        response["token_jti"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
            AuthSubcommand::List(args) => {
                self.require_admin_token()?;
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                if !args.agent.trim().is_empty() {
                    serializer.append_pair("agent_id", args.agent.trim());
                }
                if args.active_only {
                    serializer.append_pair("active_only", "true");
                }
                let query = serializer.finish();
                let path = if query.is_empty() {
                    "/v1/auth/list".to_string()
                } else {
                    format!("/v1/auth/list?{query}")
                };
                let (status, response) = self.api_request(Method::GET, &path, None, true)?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AuthSubcommand::Revoke(args) => {
                self.require_admin_token()?;
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/auth/revoke",
                    Some(json!({ "jti": args.jti.trim(), "reason": args.reason.trim() })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!("revoked {}", args.jti.trim());
                    Ok(())
                }
            }
            AuthSubcommand::Session(command) => self.cmd_auth_session(command.command),
            AuthSubcommand::Github(command) => self.cmd_auth_github(command.command),
        }
    }

    fn cmd_auth_session(&self, command: AuthSessionSubcommand) -> Result<()> {
        match command {
            AuthSessionSubcommand::Open(args) => {
                self.require_admin_token()?;
                let mut body = json!({ "agent_id": args.agent.trim(), "aud": args.aud.trim() });
                if !args.access_ttl.trim().is_empty() {
                    body["access_ttl"] = json!(args.access_ttl.trim());
                }
                if !args.refresh_ttl.trim().is_empty() {
                    body["refresh_ttl"] = json!(args.refresh_ttl.trim());
                }
                let (status, mut response) =
                    self.api_request(Method::POST, "/v1/auth/session/open", Some(body), true)?;
                ensure_status(status, 200, &response)?;
                let refresh_token = response["refresh_token"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if refresh_token.trim().is_empty() {
                    bail!("open session response missing refresh_token");
                }
                write_secret_file(&args.refresh_token_out, &refresh_token)?;
                if let Some(object) = response.as_object_mut() {
                    object.remove("refresh_token");
                    object.insert(
                        "refresh_token_file".to_string(),
                        json!(PathBuf::from(args.refresh_token_out).display().to_string()),
                    );
                }
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "session_id={}",
                        response["session_id"].as_str().unwrap_or_default()
                    );
                    println!(
                        "access_token={}",
                        response["access_token"].as_str().unwrap_or_default()
                    );
                    println!(
                        "refresh_token_file={}",
                        response["refresh_token_file"].as_str().unwrap_or_default()
                    );
                    println!(
                        "access_expires_at={}",
                        response["access_expires_at"].as_str().unwrap_or_default()
                    );
                    println!(
                        "refresh_expires_at={}",
                        response["refresh_expires_at"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
            AuthSessionSubcommand::Refresh(args) => {
                let out_path = args
                    .refresh_token_out
                    .unwrap_or_else(|| args.refresh_token_file.clone());
                guard_managed_refresh_token_rotation(
                    Path::new(&args.refresh_token_file),
                    Path::new(&out_path),
                )?;
                let refresh_token = read_secret_file(&args.refresh_token_file)?;
                let (status, mut response) = self.api_request(
                    Method::POST,
                    "/v1/auth/session/refresh",
                    Some(json!({ "refresh_token": refresh_token })),
                    false,
                )?;
                ensure_status(status, 200, &response)?;
                let next_refresh_token = response["refresh_token"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if next_refresh_token.trim().is_empty() {
                    bail!("refresh response missing refresh_token");
                }
                write_secret_file(&out_path, &next_refresh_token)?;
                if let Some(object) = response.as_object_mut() {
                    object.remove("refresh_token");
                    object.insert("refresh_token_file".to_string(), json!(out_path));
                }
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "session_id={}",
                        response["session_id"].as_str().unwrap_or_default()
                    );
                    println!(
                        "access_token={}",
                        response["access_token"].as_str().unwrap_or_default()
                    );
                    println!(
                        "refresh_token_file={}",
                        response["refresh_token_file"].as_str().unwrap_or_default()
                    );
                    println!(
                        "access_expires_at={}",
                        response["access_expires_at"].as_str().unwrap_or_default()
                    );
                    println!(
                        "refresh_expires_at={}",
                        response["refresh_expires_at"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
            AuthSessionSubcommand::Close(args) => {
                let refresh_token = if let Some(path) = args.refresh_token_file {
                    read_secret_file(&path)?
                } else {
                    String::new()
                };
                let use_token = !args.session_id.trim().is_empty();
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/auth/session/close",
                    Some(json!({
                        "session_id": args.session_id.trim(),
                        "refresh_token": refresh_token
                    })),
                    use_token,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "closed session {}",
                        response["session_id"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
        }
    }

    fn cmd_get(&self, args: GetArgs) -> Result<()> {
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/get",
            Some(json!({ "repo": args.repo, "env": args.env, "key": args.key })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        if self.json || args.format.trim() == "json" {
            print_json(&response)
        } else {
            println!("{}", response["value"].as_str().unwrap_or_default());
            Ok(())
        }
    }

    fn cmd_set(&self, args: SetArgs) -> Result<()> {
        let value = resolve_set_value(&args)?;
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/set",
            Some(json!({
                "repo": args.repo,
                "env": args.env,
                "key": args.key,
                "value": value,
                "cas_version": args.cas_version
            })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        if self.json {
            print_json(&response)
        } else {
            println!("ok");
            Ok(())
        }
    }

    fn cmd_list(&self, args: ListArgs) -> Result<()> {
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/list",
            Some(json!({ "repo": args.repo, "env": args.env, "prefix": args.prefix })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        if self.json {
            print_json(&response)
        } else if let Some(keys) = response["keys"].as_array() {
            for key in keys {
                println!("{}", key.as_str().unwrap_or_default());
            }
            Ok(())
        } else {
            print_json(&response)
        }
    }

    fn cmd_batch_get(&self, args: BatchGetArgs) -> Result<()> {
        let keys = split_csv(&args.keys);
        if keys.is_empty() {
            bail!("--keys must include at least one key");
        }
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/batch-get",
            Some(json!({ "repo": args.repo, "env": args.env, "keys": keys })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        if self.json {
            print_json(&response)
        } else if let Some(values) = response["values"].as_object() {
            for (key, value) in values {
                println!("{key}={}", value.as_str().unwrap_or_default());
            }
            Ok(())
        } else {
            print_json(&response)
        }
    }

    fn cmd_scope(&self, command: ScopeSubcommand) -> Result<()> {
        self.require_admin_token()?;
        match command {
            ScopeSubcommand::Ensure(args) => {
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/scopes/ensure",
                    Some(json!({ "repo": args.repo, "env": args.env })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "scope {}/{} {}",
                        response["repo"].as_str().unwrap_or_default(),
                        response["env"].as_str().unwrap_or_default(),
                        if response["created"].as_bool().unwrap_or(false) {
                            "created"
                        } else {
                            "exists"
                        }
                    );
                    Ok(())
                }
            }
        }
    }

    fn cmd_run(&self, args: RunArgs) -> Result<()> {
        let keys = split_csv(&args.keys);
        if keys.is_empty() {
            bail!("--keys must include at least one key");
        }
        let ttl_seconds = parse_duration_seconds(&args.ttl, Duration::from_secs(60))?;
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/run/session/open",
            Some(json!({
                "repo": args.repo,
                "env": args.env,
                "keys": keys,
                "mode": args.mode,
                "ttl_seconds": ttl_seconds
            })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        let session_id = response["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let one_time_token = response["one_time_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if session_id.is_empty() || one_time_token.is_empty() {
            bail!("open session response missing session_id/one_time_token");
        }
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/run/session/materialize",
            Some(json!({ "session_id": session_id, "one_time_token": one_time_token })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        let opened_session_id = session_id.clone();
        let values = response["values"]
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| (key, value.as_str().unwrap_or_default().to_string()))
            .collect::<BTreeMap<_, _>>();
        let result = exec_with_secrets(&args.command, &values, &args.mode);
        let _ = self.api_request(
            Method::POST,
            "/v1/run/session/close",
            Some(json!({ "session_id": opened_session_id })),
            true,
        );
        result
    }

    fn cmd_rotate(&self, command: RotateSubcommand) -> Result<()> {
        match command {
            RotateSubcommand::Npm(args) => self.cmd_rotate_npm(*args),
        }
    }

    fn cmd_rotate_npm(&self, args: NpmRotateArgs) -> Result<()> {
        let spec = NpmTokenSpec::from_args(&args)?;
        let github_sink = GitHubActionsSecretSink::from_args(&args)?;
        let management_token_key = args
            .management_token_key
            .as_deref()
            .unwrap_or(args.token_key.as_str());

        if args.dry_run {
            return self.print_npm_rotation_result(json!({
                "provider": "npm",
                "dry_run": true,
                "repo": args.repo,
                "env": args.env,
                "token_key": args.token_key,
                "management_token_key": management_token_key,
                "registry": spec.registry.as_str(),
                "would_create_token": spec.safe_summary(),
                "would_update_fort": true,
                "would_revoke_old": args.revoke_old,
                "would_update_github_actions": github_sink.as_ref().map(GitHubActionsSecretSink::safe_summary),
                "secret_values_loaded": false
            }));
        }

        let old_token =
            self.get_secret_value_for_rotation(&args.repo, &args.env, &args.token_key)?;
        let management_token = if management_token_key == args.token_key {
            old_token.clone()
        } else {
            self.get_secret_value_for_rotation(&args.repo, &args.env, management_token_key)?
        };
        let password = if let Some(password_key) = args.password_key.as_deref() {
            Some(self.get_secret_value_for_rotation(&args.repo, &args.env, password_key)?)
        } else {
            None
        };

        let otp_file = args
            .otp_file
            .as_deref()
            .ok_or_else(|| anyhow!("--otp-file is required for npm token creation"))?;
        let otp = read_secret_file(otp_file).context("read npm OTP file")?;
        let created = self.create_npm_token(&spec, &management_token, password.as_deref(), &otp)?;
        let new_token = created
            .get("token")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("npm token create response missing token"))?
            .to_string();

        self.set_secret_value(&args.repo, &args.env, &args.token_key, &new_token)?;

        let github_updates = if let Some(sink) = github_sink {
            let token_repo = sink.token_repo.as_deref().unwrap_or(args.repo.as_str());
            let token_env = sink.token_env.as_deref().unwrap_or(args.env.as_str());
            let github_token =
                self.get_secret_value_for_rotation(token_repo, token_env, &sink.token_key)?;
            self.update_github_actions_secrets(&sink, &github_token, &new_token)?
        } else {
            Vec::new()
        };

        let mut revoked_old = false;
        if args.revoke_old {
            let revoke_otp = if let Some(path) = args.revoke_otp_file.as_deref() {
                read_secret_file(path).context("read npm revoke OTP file")?
            } else {
                otp
            };
            self.delete_npm_token(&spec.registry, &management_token, &old_token, &revoke_otp)?;
            revoked_old = true;
        }

        let mut redacted_created = created;
        if let Some(object) = redacted_created.as_object_mut() {
            object.remove("token");
            object.insert("token".to_string(), json!(redact_secret(&new_token)));
        }

        self.print_npm_rotation_result(json!({
            "provider": "npm",
            "dry_run": false,
            "repo": args.repo,
            "env": args.env,
            "token_key": args.token_key,
            "management_token_key": management_token_key,
            "registry": spec.registry.as_str(),
            "created": redacted_created,
            "fort_updated": true,
            "github_actions_updated": github_updates,
            "old_token_revoked": revoked_old
        }))
    }

    fn cmd_agent(&self, command: AgentSubcommand) -> Result<()> {
        match command {
            AgentSubcommand::Create(args) => {
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/agents",
                    Some(json!({
                        "id": args.id,
                        "type": args.agent_type,
                        "status": args.status
                    })),
                    true,
                )?;
                ensure_status(status, 201, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!("created agent {}", args.id);
                    Ok(())
                }
            }
            AgentSubcommand::Get(args) => {
                let (status, response) =
                    self.api_request(Method::GET, &format!("/v1/agents/{}", args.id), None, true)?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentSubcommand::List(args) => {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                if let Some(agent_type) = args
                    .agent_type
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                {
                    serializer.append_pair("type", agent_type.trim());
                }
                if let Some(status) = args
                    .status
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                {
                    serializer.append_pair("status", status.trim());
                }
                let query = serializer.finish();
                let path = if query.is_empty() {
                    "/v1/agents".to_string()
                } else {
                    format!("/v1/agents?{query}")
                };
                let (status, response) = self.api_request(Method::GET, &path, None, true)?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentSubcommand::SetStatus(args) => {
                let endpoint = if args.status.trim() == "active" {
                    format!("/v1/agents/{}/enable", args.id)
                } else {
                    format!("/v1/agents/{}/disable", args.id)
                };
                let (status, response) =
                    self.api_request(Method::POST, &endpoint, Some(json!({})), true)?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentSubcommand::Rotate(args) => {
                let (status, response) = self.api_request(
                    Method::POST,
                    &format!("/v1/agents/{}/rotate", args.id),
                    Some(json!({})),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentSubcommand::Remove(args) => {
                let _ = args.force;
                let (status, response) = self.api_request(
                    Method::DELETE,
                    &format!("/v1/agents/{}", args.id),
                    None,
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!("removed agent {}", args.id);
                    Ok(())
                }
            }
            AgentSubcommand::Policy(command) => self.cmd_agent_policy(command.command),
        }
    }

    fn cmd_agent_policy(&self, command: AgentPolicySubcommand) -> Result<()> {
        match command {
            AgentPolicySubcommand::Get(args) => {
                let (status, response) = self.api_request(
                    Method::GET,
                    &format!("/v1/agents/{}/policy", args.id),
                    None,
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentPolicySubcommand::Set(args) => {
                let bindings = args
                    .binds
                    .iter()
                    .map(|raw| parse_binding(raw))
                    .collect::<Result<Vec<_>>>()?;
                let (status, response) = self.api_request(
                    Method::PUT,
                    &format!("/v1/agents/{}/policy", args.id),
                    Some(json!({ "bindings": bindings })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentPolicySubcommand::Add(args) => {
                let binding = parse_binding(&args.bind)?;
                let (status, response) = self.api_request(
                    Method::POST,
                    &format!("/v1/agents/{}/policy/add", args.id),
                    Some(json!({ "binding": binding })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentPolicySubcommand::Remove(args) => {
                let binding = parse_binding(&args.bind)?;
                let (status, response) = self.api_request(
                    Method::POST,
                    &format!("/v1/agents/{}/policy/remove", args.id),
                    Some(json!({ "binding": binding })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
            AgentPolicySubcommand::Check(args) => {
                let (status, response) = self.api_request(
                    Method::POST,
                    &format!("/v1/agents/{}/policy/check", args.id),
                    Some(json!({ "repo": args.repo, "env": args.env, "op": args.op })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                print_json(&response)
            }
        }
    }

    fn cmd_auth_github(&self, command: AuthGithubSubcommand) -> Result<()> {
        match command {
            AuthGithubSubcommand::Login(args) => {
                require_pat_tls(&self.host)?;
                let stored_path = stored_pat_path().context("resolve fort config directory")?;
                let stored_path_str = stored_path.display().to_string();
                let mut store_prompted = false;
                let mut used_stored = false;
                let pat = match args.pat_file.as_deref() {
                    Some(path) => read_secret_file(path).context("read --pat-file")?,
                    None if stored_path.exists() => {
                        used_stored = true;
                        read_secret_file(&stored_path_str).context("read stored PAT")?
                    }
                    None => {
                        store_prompted = true;
                        prompt_pat()?
                    }
                };
                let mut body = json!({ "pat": pat, "aud": args.aud.trim() });
                if !args.access_ttl.trim().is_empty() {
                    body["access_ttl"] = json!(args.access_ttl.trim());
                }
                if !args.refresh_ttl.trim().is_empty() {
                    body["refresh_ttl"] = json!(args.refresh_ttl.trim());
                }
                let (status, response) =
                    self.api_request(Method::POST, "/v1/auth/github/login", Some(body), false)?;
                match ensure_status(status, 200, &response) {
                    Ok(()) => {}
                    Err(err) if used_stored => {
                        return Err(err).with_context(|| {
                            format!(
                                "login with stored PAT failed; delete {stored_path_str} or pass --pat-file to use a new one"
                            )
                        });
                    }
                    Err(err) => return Err(err),
                }
                let access_token = response["access_token"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let refresh_token = response["refresh_token"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if access_token.trim().is_empty() || refresh_token.trim().is_empty() {
                    bail!("github login response missing tokens");
                }
                if store_prompted {
                    write_secret_file(&stored_path_str, &pat).context("store entered PAT")?;
                }
                let session_dir = fort_session_dir().context("resolve fort session directory")?;
                let access_path = session_dir.join("access.token").display().to_string();
                let refresh_path = session_dir.join("refresh.token").display().to_string();
                write_secret_file(&access_path, &access_token)?;
                write_secret_file(&refresh_path, &refresh_token)?;
                let summary = json!({
                    "session_id": response["session_id"].as_str().unwrap_or_default(),
                    "agent_id": response["agent_id"].as_str().unwrap_or_default(),
                    "github_login": response["github_login"].as_str().unwrap_or_default(),
                    "access_token_file": access_path,
                    "refresh_token_file": refresh_path,
                    "access_expires_at": response["access_expires_at"].as_str().unwrap_or_default(),
                    "refresh_expires_at": response["refresh_expires_at"].as_str().unwrap_or_default(),
                });
                if self.json {
                    print_json(&summary)
                } else {
                    println!(
                        "logged in as {} (github {})",
                        response["agent_id"].as_str().unwrap_or_default(),
                        response["github_login"].as_str().unwrap_or_default()
                    );
                    println!("access_token_file={access_path}");
                    println!("refresh_token_file={refresh_path}");
                    Ok(())
                }
            }
            AuthGithubSubcommand::Logout => {
                let refresh_path =
                    managed_refresh_token_path().context("resolve fort session directory")?;
                if !Path::new(&refresh_path).exists() {
                    bail!("no managed session to close");
                }
                let refresh_token =
                    read_secret_file(&refresh_path).context("read managed refresh token")?;
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/auth/session/close",
                    Some(json!({ "refresh_token": refresh_token })),
                    false,
                )?;
                ensure_status(status, 200, &response)?;
                let access_path =
                    managed_access_token_path().context("resolve fort session directory")?;
                let _ = fs::remove_file(&access_path);
                let _ = fs::remove_file(&refresh_path);
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "logged out; closed session {}",
                        response["session_id"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
            AuthGithubSubcommand::Enroll(args) => {
                self.require_admin_token()?;
                require_pat_tls(&self.host)?;
                let pat = read_secret_file(&args.pat_file).context("read --pat-file")?;
                let (status, response) = self.api_request(
                    Method::POST,
                    "/v1/auth/github/enroll",
                    Some(json!({ "agent_id": args.agent.trim(), "pat": pat })),
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!(
                        "enrolled {} (github {}, fingerprint {})",
                        response["agent_id"].as_str().unwrap_or_default(),
                        response["github_login"].as_str().unwrap_or_default(),
                        response["fingerprint_prefix"].as_str().unwrap_or_default()
                    );
                    Ok(())
                }
            }
            AuthGithubSubcommand::Unenroll(args) => {
                self.require_admin_token()?;
                let (status, response) = self.api_request(
                    Method::DELETE,
                    &format!(
                        "/v1/auth/github/fingerprints/{}",
                        encode_path_segment(args.agent.trim())
                    ),
                    None,
                    true,
                )?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    println!("unenrolled {}", args.agent.trim());
                    Ok(())
                }
            }
            AuthGithubSubcommand::List => {
                self.require_admin_token()?;
                let (status, response) =
                    self.api_request(Method::GET, "/v1/auth/github/fingerprints", None, true)?;
                ensure_status(status, 200, &response)?;
                if self.json {
                    print_json(&response)
                } else {
                    let entries = response["fingerprints"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if entries.is_empty() {
                        println!("no enrolled fingerprints");
                    }
                    for entry in entries {
                        println!(
                            "{} github={} fingerprint={} enrolled={}",
                            entry["agent_id"].as_str().unwrap_or_default(),
                            entry["github_login"].as_str().unwrap_or_default(),
                            entry["fingerprint_prefix"].as_str().unwrap_or_default(),
                            entry["created_at"].as_str().unwrap_or_default()
                        );
                    }
                    Ok(())
                }
            }
        }
    }

    fn require_admin_token(&self) -> Result<()> {
        if self.token.trim().is_empty() {
            bail!(
                "admin token file auth required (--token-file or FORT_TOKEN_PATH/FORT_BOOTSTRAP_TOKEN_FILE)"
            );
        }
        Ok(())
    }

    fn get_secret_value(&self, repo: &str, env: &str, key: &str) -> Result<String> {
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/get",
            Some(json!({ "repo": repo, "env": env, "key": key })),
            true,
        )?;
        ensure_status(status, 200, &response)?;
        response["value"]
            .as_str()
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("fort secret {repo}/{env}/{key} is empty or missing"))
    }

    fn get_secret_value_for_rotation(&self, repo: &str, env: &str, key: &str) -> Result<String> {
        self.get_secret_value(repo, env, key).with_context(|| {
            format!("missing required secret for npm rotation: {repo}/{env}/{key}")
        })
    }

    fn set_secret_value(&self, repo: &str, env: &str, key: &str, value: &str) -> Result<()> {
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/set",
            Some(json!({
                "repo": repo,
                "env": env,
                "key": key,
                "value": value,
            })),
            true,
        )?;
        ensure_status(status, 200, &response)
    }

    fn create_npm_token(
        &self,
        spec: &NpmTokenSpec,
        management_token: &str,
        password: Option<&str>,
        otp: &str,
    ) -> Result<Value> {
        let url = spec
            .registry
            .join("-/npm/v1/tokens")
            .context("build npm token create url")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(management_token.trim())
            .header("npm-otp", otp.trim())
            .header("npm-auth-type", "web")
            .header("npm-command", "token")
            .json(&spec.create_body(password))
            .send()
            .context("send npm token create request")?;
        let status = response.status().as_u16();
        let body = response.json::<Value>().unwrap_or_else(|_| json!({}));
        if status != 201 {
            if password.is_none() && status == 400 {
                let message = npm_error(&body);
                if message.to_lowercase().contains("password") {
                    bail!(
                        "npm token create rejected passwordless mode (status=400): {}. Provide --password-key for this token-management credential.",
                        message
                    );
                }
            }
            bail!(
                "npm token create failed (status={}): {}",
                status,
                npm_error(&body)
            );
        }
        Ok(body)
    }

    fn delete_npm_token(
        &self,
        registry: &Url,
        management_token: &str,
        old_token: &str,
        otp: &str,
    ) -> Result<()> {
        let encoded_token =
            url::form_urlencoded::byte_serialize(old_token.trim().as_bytes()).collect::<String>();
        let path = format!("-/npm/v1/tokens/token/{encoded_token}");
        let url = registry.join(&path).context("build npm token delete url")?;
        let response = self
            .http
            .delete(url)
            .bearer_auth(management_token.trim())
            .header("npm-otp", otp.trim())
            .header("npm-auth-type", "web")
            .header("npm-command", "token")
            .send()
            .context("send npm token delete request")?;
        let status = response.status().as_u16();
        if status == 204 {
            return Ok(());
        }
        let body = response.json::<Value>().unwrap_or_else(|_| json!({}));
        bail!(
            "npm token delete failed (status={}): {}",
            status,
            npm_error(&body)
        );
    }

    fn update_github_actions_secrets(
        &self,
        sink: &GitHubActionsSecretSink,
        github_token: &str,
        value: &str,
    ) -> Result<Vec<Value>> {
        let mut updates = Vec::with_capacity(sink.repos.len());
        for repo in &sink.repos {
            let key_url = sink
                .api_base
                .join(&format!(
                    "repos/{}/{}/actions/secrets/public-key",
                    encode_path_segment(&repo.owner),
                    encode_path_segment(&repo.name)
                ))
                .context("build github actions public key url")?;
            let key_response = self
                .github_request(Method::GET, key_url, github_token, None)?
                .json::<Value>()
                .unwrap_or_else(|_| json!({}));
            let key = key_response
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let key_id = key_response
                .get("key_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if key.is_empty() || key_id.is_empty() {
                bail!("github actions public key response missing key/key_id");
            }
            let encrypted_value = encrypt_github_actions_secret_value(key, value)?;
            let secret_url = sink
                .api_base
                .join(&format!(
                    "repos/{}/{}/actions/secrets/{}",
                    encode_path_segment(&repo.owner),
                    encode_path_segment(&repo.name),
                    encode_path_segment(&sink.secret_name)
                ))
                .context("build github actions secret url")?;
            let status = self
                .github_request(
                    Method::PUT,
                    secret_url,
                    github_token,
                    Some(json!({
                        "encrypted_value": encrypted_value,
                        "key_id": key_id
                    })),
                )?
                .status()
                .as_u16();
            if !matches!(status, 201 | 204) {
                bail!("github actions secret update failed with status {status}");
            }
            updates.push(json!({
                "repo": repo.raw,
                "secret": sink.secret_name,
                "status": status
            }));
        }
        Ok(updates)
    }

    fn github_request(
        &self,
        method: Method,
        url: Url,
        github_token: &str,
        body: Option<Value>,
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(github_token.trim())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "fort");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().context("send github request")?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let body = response.json::<Value>().unwrap_or_else(|_| json!({}));
        bail!(
            "github request failed (status={}): {}",
            status,
            github_error(&body)
        );
    }

    fn print_npm_rotation_result(&self, value: Value) -> Result<()> {
        if self.json {
            print_json(&value)
        } else if value
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            println!("npm rotation dry run ok");
            println!(
                "token_key={}",
                value["token_key"].as_str().unwrap_or_default()
            );
            println!(
                "management_token_key={}",
                value["management_token_key"].as_str().unwrap_or_default()
            );
            println!(
                "registry={}",
                value["registry"].as_str().unwrap_or_default()
            );
            Ok(())
        } else {
            println!("npm token rotated");
            println!(
                "token_key={}",
                value["token_key"].as_str().unwrap_or_default()
            );
            println!(
                "new_token_key={}",
                value["created"]["key"].as_str().unwrap_or_default()
            );
            println!(
                "old_token_revoked={}",
                value["old_token_revoked"].as_bool().unwrap_or(false)
            );
            Ok(())
        }
    }
}

#[derive(Debug)]
struct NpmTokenSpec {
    registry: Url,
    name: String,
    description: String,
    expires_days: i64,
    packages: Vec<String>,
    scopes: Vec<String>,
    orgs: Vec<String>,
    cidr: Vec<String>,
    packages_permission: String,
    orgs_permission: String,
    bypass_2fa: bool,
}

impl NpmTokenSpec {
    fn from_args(args: &NpmRotateArgs) -> Result<Self> {
        let registry = Url::parse(args.registry.trim())
            .with_context(|| format!("invalid npm registry {}", args.registry.trim()))?;
        if !matches!(registry.scheme(), "https" | "http") {
            bail!("npm registry must be http or https");
        }
        let packages_permission = normalize_npm_permission(&args.packages_permission)?;
        let orgs_permission = normalize_npm_permission(&args.orgs_permission)?;
        if args.name.trim().is_empty() {
            bail!("--name is required");
        }
        if args.expires_days < 1 {
            bail!("--expires-days must be at least 1");
        }
        if packages_permission == "read-write" && args.expires_days > 90 {
            bail!("npm read-write token expiration cannot exceed 90 days");
        }
        let packages = clean_repeated_values(&args.packages);
        let scopes = clean_repeated_values(&args.scopes);
        let orgs = clean_repeated_values(&args.orgs);
        let cidr = clean_repeated_values(&args.cidr);
        if args.all_packages && !packages.is_empty() {
            bail!("use either --all-packages or explicit --package values, not both");
        }
        let packages = if args.all_packages {
            vec!["*".to_string()]
        } else {
            packages
        };
        if packages.is_empty() && scopes.is_empty() && orgs.is_empty() {
            bail!("npm rotation requires --package, --scope, --org, or explicit --all-packages");
        }
        if packages_permission == "no-access" && (!packages.is_empty() || !scopes.is_empty()) {
            bail!("packages/scopes were provided but --packages-permission is no-access");
        }
        if orgs_permission == "no-access" && !orgs.is_empty() {
            bail!("orgs were provided but --orgs-permission is no-access");
        }

        Ok(Self {
            registry,
            name: args.name.trim().to_string(),
            description: args.description.trim().to_string(),
            expires_days: args.expires_days,
            packages,
            scopes,
            orgs,
            cidr,
            packages_permission,
            orgs_permission,
            bypass_2fa: args.bypass_2fa,
        })
    }

    fn create_body(&self, password: Option<&str>) -> Value {
        let expires = (Utc::now() + ChronoDuration::days(self.expires_days))
            .format("%Y-%m-%d")
            .to_string();
        let mut body = json!({
            "name": self.name,
            "expires": expires,
            "bypass_2fa": self.bypass_2fa,
            "packages": self.packages,
            "scopes": self.scopes,
            "orgs": self.orgs,
            "packages_and_scopes_permission": self.packages_permission,
            "orgs_permission": self.orgs_permission
        });
        if let Some(password) = password {
            body["password"] = json!(password);
        }
        if !self.description.is_empty() {
            body["token_description"] = json!(self.description);
        }
        if !self.cidr.is_empty() {
            body["cidr"] = json!(self.cidr);
        }
        body
    }

    fn safe_summary(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "expires_days": self.expires_days,
            "packages": self.packages,
            "scopes": self.scopes,
            "orgs": self.orgs,
            "cidr": self.cidr,
            "packages_permission": self.packages_permission,
            "orgs_permission": self.orgs_permission,
            "bypass_2fa": self.bypass_2fa
        })
    }
}

#[derive(Debug)]
struct GitHubActionsSecretSink {
    repos: Vec<GitHubRepoRef>,
    secret_name: String,
    token_key: String,
    token_repo: Option<String>,
    token_env: Option<String>,
    api_base: Url,
}

impl GitHubActionsSecretSink {
    fn from_args(args: &NpmRotateArgs) -> Result<Option<Self>> {
        let repos = clean_repeated_values(&args.github_actions_repos)
            .into_iter()
            .map(|raw| GitHubRepoRef::parse(&raw))
            .collect::<Result<Vec<_>>>()?;
        if repos.is_empty() {
            if args.github_token_key.is_some()
                || !args.github_secret_name.trim().is_empty()
                || args.github_token_repo.is_some()
                || args.github_token_env.is_some()
                || args.github_api_base.trim() != "https://api.github.com"
            {
                bail!(
                    "--github-actions-repo is required when GitHub Actions secret options are set"
                );
            }
            return Ok(None);
        }
        let token_key = args
            .github_token_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("--github-token-key is required with --github-actions-repo"))?
            .to_string();
        let token_repo = args
            .github_token_repo
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let token_env = args
            .github_token_env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if token_repo.is_some() ^ token_env.is_some() {
            bail!("--github-token-repo and --github-token-env must be provided together");
        }
        let secret_name = args
            .github_secret_name
            .trim()
            .to_string()
            .if_empty_then(|| args.token_key.trim().to_string());
        validate_github_secret_name(&secret_name)?;
        let api_base = Url::parse(args.github_api_base.trim())
            .with_context(|| format!("invalid GitHub API base {}", args.github_api_base.trim()))?;
        if !matches!(api_base.scheme(), "https" | "http") {
            bail!("GitHub API base must be http or https");
        }
        Ok(Some(Self {
            repos,
            secret_name,
            token_key,
            token_repo,
            token_env,
            api_base,
        }))
    }

    fn safe_summary(&self) -> Value {
        json!({
            "repos": self.repos.iter().map(|repo| repo.raw.clone()).collect::<Vec<_>>(),
            "secret_name": self.secret_name,
            "token_key": self.token_key,
            "token_repo": self.token_repo,
            "token_env": self.token_env,
            "api_base": self.api_base.as_str()
        })
    }
}

#[derive(Debug)]
struct GitHubRepoRef {
    raw: String,
    owner: String,
    name: String,
}

impl GitHubRepoRef {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (owner, name) = raw
            .split_once('/')
            .ok_or_else(|| anyhow!("GitHub repo must use owner/name form"))?;
        let owner = owner.trim();
        let name = name.trim();
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            bail!("GitHub repo must use owner/name form");
        }
        Ok(Self {
            raw: format!("{owner}/{name}"),
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }
}

trait EmptyStringExt {
    fn if_empty_then(self, fallback: impl FnOnce() -> String) -> String;
}

impl EmptyStringExt for String {
    fn if_empty_then(self, fallback: impl FnOnce() -> String) -> String {
        if self.is_empty() { fallback() } else { self }
    }
}

fn resolve_host(flag_host: Option<String>) -> Result<String> {
    let candidate = flag_host
        .unwrap_or_else(|| env::var("FORT_HOST").unwrap_or_default())
        .trim()
        .to_string();
    let candidate = if candidate.is_empty() {
        host_from_settings()
    } else {
        candidate
    };
    if candidate.trim().is_empty() {
        bail!(
            "fort host is required (set --host, FORT_HOST, or ~/.fort/settings.toml [fort].host)"
        );
    }
    let parsed = Url::parse(candidate.trim())
        .with_context(|| format!("invalid host {}", candidate.trim()))?;
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

struct ResolvedToken {
    token: String,
    managed: bool,
}

fn resolve_token(flag_token_file: Option<String>) -> Result<ResolvedToken> {
    if let Some(path) = flag_token_file {
        return Ok(ResolvedToken {
            token: read_secret_file(&path)?,
            managed: false,
        });
    }
    for path in [
        env::var("FORT_TOKEN_PATH").unwrap_or_default(),
        env::var("FORT_BOOTSTRAP_TOKEN_FILE").unwrap_or_default(),
    ] {
        if path.trim().is_empty() {
            continue;
        }
        if let Ok(token) = read_secret_file(&path) {
            return Ok(ResolvedToken {
                token,
                managed: false,
            });
        }
    }
    if let Some(path) = managed_access_token_path()
        && let Ok(token) = read_secret_file(&path)
    {
        return Ok(ResolvedToken {
            token,
            managed: true,
        });
    }
    Ok(ResolvedToken {
        token: String::new(),
        managed: false,
    })
}

fn fort_session_dir() -> Option<PathBuf> {
    let explicit = env::var("FORT_SESSION_DIR").unwrap_or_default();
    if !explicit.trim().is_empty() {
        return Some(PathBuf::from(explicit.trim()));
    }
    let home = env::var("HOME").ok()?;
    if home.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(home.trim()).join(".fort/session"))
}

fn managed_access_token_path() -> Option<String> {
    fort_session_dir().map(|dir| dir.join("access.token").display().to_string())
}

fn managed_refresh_token_path() -> Option<String> {
    fort_session_dir().map(|dir| dir.join("refresh.token").display().to_string())
}

fn stored_pat_path() -> Option<PathBuf> {
    let session_dir = fort_session_dir()?;
    match session_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Some(parent.join("github.pat")),
        _ => Some(session_dir.join("github.pat")),
    }
}

fn prompt_pat() -> Result<String> {
    eprint!("GitHub PAT: ");
    io::stderr().flush().ok();
    let pat = read_hidden_line().context("read PAT")?;
    eprintln!();
    let pat = pat.trim().to_string();
    if pat.is_empty() {
        bail!("no PAT entered; pass --pat-file <path> or enter a PAT when prompted");
    }
    Ok(pat)
}

fn read_hidden_line() -> Result<String> {
    use std::io::BufRead;
    let stdin = io::stdin();
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line);
    }
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line);
    }
    let mut hidden: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut hidden) } != 0 {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line);
    }
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) };
    let mut line = String::new();
    let result = stdin.lock().read_line(&mut line);
    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &original) };
    result?;
    Ok(line)
}

const MANAGED_REFRESH_SKEW_SECONDS: i64 = 30;

fn token_needs_refresh(token: &str) -> bool {
    let Some(exp) = jwt_exp(token) else {
        return true;
    };
    exp <= Utc::now().timestamp() + MANAGED_REFRESH_SKEW_SECONDS
}

fn jwt_exp(token: &str) -> Option<i64> {
    let mut parts = token.trim().split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    value.get("exp")?.as_i64()
}

fn guard_managed_refresh_token_rotation(
    refresh_token_file: &Path,
    refresh_token_out: &Path,
) -> Result<()> {
    if !is_managed_refresh_token_path(refresh_token_file) {
        return Ok(());
    }
    let refresh_token_file = normalize_path_components(refresh_token_file.to_path_buf());
    let refresh_token_out = normalize_path_components(refresh_token_out.to_path_buf());
    if refresh_token_file != refresh_token_out {
        bail!(
            "refusing to rotate managed Fort refresh token {} into {}; managed refresh tokens must be refreshed in place",
            refresh_token_file.display(),
            refresh_token_out.display()
        );
    }
    Ok(())
}

fn is_managed_refresh_token_path(path: &Path) -> bool {
    let normalized = normalize_path_components(path.to_path_buf());
    let parts = normalized
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    parts.len() >= 3
        && parts[parts.len() - 1] == "refresh.token"
        && parts[parts.len() - 2] == "session"
        && parts[parts.len() - 3] == ".fort"
}

fn normalize_path_components(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// GitHub PATs are bearer credentials: refuse to send one over plaintext HTTP
/// except to loopback hosts (isolated integration tests).
fn require_pat_tls(host: &str) -> Result<()> {
    let url = Url::parse(host.trim()).context("invalid host")?;
    if url.scheme() == "https" {
        return Ok(());
    }
    match url.host_str().unwrap_or("").trim() {
        "localhost" | "127.0.0.1" | "::1" => Ok(()),
        _ => bail!("refusing to send a GitHub PAT over non-TLS host {host}; use https"),
    }
}

fn reject_deprecated_token_value_env() -> Result<()> {
    if !env::var("FORT_TOKEN").unwrap_or_default().trim().is_empty() {
        bail!(
            "FORT_TOKEN is deprecated and disallowed; use file-based auth (FORT_TOKEN_PATH or FORT_BOOTSTRAP_TOKEN_FILE)"
        );
    }
    if !env::var("FORT_REFRESH_TOKEN")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        bail!(
            "FORT_REFRESH_TOKEN is deprecated and disallowed; use file-based auth (FORT_REFRESH_TOKEN_PATH)"
        );
    }
    Ok(())
}

fn read_secret_file(path: &str) -> Result<String> {
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        bail!("secret path is empty");
    }
    let metadata = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("secret path is not a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("secret file permissions must be 0600 or stricter");
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let value = raw.trim().to_string();
    if value.is_empty() {
        bail!("secret file is empty");
    }
    Ok(value)
}

fn resolve_set_value(args: &SetArgs) -> Result<String> {
    match args.value_file.as_deref() {
        Some(path) => read_secret_file(path).context("read --value-file"),
        None => Ok(args.value.clone().unwrap_or_default()),
    }
}

fn write_secret_file(path: &str, value: &str) -> Result<()> {
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        bail!("secret path is empty");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, value.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn split_csv(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for key in raw.split(',').map(str::trim).filter(|key| !key.is_empty()) {
        if out.iter().any(|existing| existing == key) {
            continue;
        }
        out.push(key.to_string());
    }
    out
}

fn clean_repeated_values(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in raw
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if out.iter().any(|existing| existing == value) {
            continue;
        }
        out.push(value.to_string());
    }
    out
}

fn normalize_npm_permission(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "read-only" | "read-write" | "no-access" => Ok(normalized),
        _ => bail!("npm permission must be read-only, read-write, or no-access"),
    }
}

fn redact_secret(secret: &str) -> String {
    let secret = secret.trim();
    if secret.is_empty() {
        return "<empty>".to_string();
    }
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 12 {
        return format!("{}...", chars.iter().take(4).collect::<String>());
    }
    format!(
        "{}...{}",
        chars.iter().take(8).collect::<String>(),
        chars
            .iter()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    )
}

fn npm_error(body: &Value) -> String {
    body.get("error")
        .or_else(|| body.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("request failed")
        .to_string()
}

fn github_error(body: &Value) -> String {
    body.get("message")
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("request failed")
        .to_string()
}

fn validate_github_secret_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("GitHub secret name is required");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        bail!("GitHub secret name must contain only A-Z, 0-9, and _");
    }
    if name.starts_with("GITHUB_") {
        bail!("GitHub secret name must not start with GITHUB_");
    }
    Ok(())
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn encrypt_github_actions_secret_value(public_key: &str, plaintext: &str) -> Result<String> {
    let pub_bytes = BASE64
        .decode(public_key.trim())
        .context("decode github actions public key")?;
    if pub_bytes.len() != 32 {
        bail!(
            "invalid github actions public key length: {}",
            pub_bytes.len()
        );
    }
    let recipient_pub = CryptoBoxPublicKey::from(
        <[u8; 32]>::try_from(pub_bytes.as_slice())
            .map_err(|_| anyhow!("invalid github actions public key length"))?,
    );
    let ephemeral_secret = CryptoBoxSecretKey::generate(&mut OsRng);
    let ephemeral_pub_bytes = ephemeral_secret.public_key().as_bytes().to_owned();
    let mut nonce_hash = Blake2bVar::new(24).context("init github actions secret nonce hash")?;
    nonce_hash.update(&ephemeral_pub_bytes);
    nonce_hash.update(recipient_pub.as_bytes());
    let mut nonce_bytes = [0_u8; 24];
    nonce_hash
        .finalize_variable(&mut nonce_bytes)
        .context("finalize github actions secret nonce hash")?;
    let nonce = GenericArray::clone_from_slice(&nonce_bytes);
    let cipher = SalsaBox::new(&recipient_pub, &ephemeral_secret);
    let sealed = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|err| anyhow!("encrypt github actions secret: {err}"))?;
    let mut out = Vec::with_capacity(ephemeral_pub_bytes.len() + sealed.len());
    out.extend_from_slice(&ephemeral_pub_bytes);
    out.extend_from_slice(&sealed);
    Ok(BASE64.encode(out))
}

fn parse_duration_seconds(raw: &str, fallback: Duration) -> Result<i64> {
    if raw.trim().is_empty() {
        return Ok(fallback.as_secs() as i64);
    }
    if let Ok(seconds) = raw.trim().parse::<i64>()
        && seconds > 0
    {
        return Ok(seconds);
    }
    let mut number = String::new();
    let mut total = 0i64;
    for ch in raw.trim().chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        let value = number.parse::<i64>().context("invalid duration")?;
        number.clear();
        total += match ch {
            's' => value,
            'm' => value * 60,
            'h' => value * 60 * 60,
            'd' => value * 60 * 60 * 24,
            _ => bail!("invalid duration"),
        };
    }
    if !number.is_empty() || total <= 0 {
        bail!("invalid duration");
    }
    Ok(total)
}

fn parse_binding(raw: &str) -> Result<Binding> {
    let parts = raw.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("binding format must be <repo|*>:<env|*>:<ops|*>");
    }
    let repo = parts[0].trim();
    let env = parts[1].trim();
    let ops_raw = parts[2].trim();
    if repo.is_empty() || env.is_empty() || ops_raw.is_empty() {
        bail!("binding parts cannot be empty");
    }
    let ops = split_csv(ops_raw)
        .into_iter()
        .map(|name| Operation::parse(&name).ok_or_else(|| anyhow::anyhow!("invalid op {}", name)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Binding {
        repo: repo.to_string(),
        env: env.to_string(),
        ops,
    })
}

fn ensure_status(status: u16, expected: u16, body: &Value) -> Result<()> {
    if status == expected {
        return Ok(());
    }
    let message = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    bail!("fort request failed (status={}): {}", status, message);
}

fn print_json(value: &Value) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, value)?;
    writeln!(&mut handle)?;
    Ok(())
}

fn exec_with_secrets(
    command: &[String],
    values: &BTreeMap<String, String>,
    mode: &str,
) -> Result<()> {
    if command.is_empty() {
        bail!("run requires a command after --");
    }
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());
    let mut envv = sanitized_child_env(env::vars().collect());
    let mut cleanup_dir: Option<PathBuf> = None;
    if mode.trim() == "env" {
        for (key, value) in values {
            envv.insert(key.clone(), value.clone());
        }
    } else {
        let dir = tempfile::Builder::new()
            .prefix("fort-secrets-")
            .tempdir()
            .context("create temp secrets dir")?;
        for (key, value) in values {
            let safe_key = key.replace('/', "_");
            let path = dir.path().join(safe_key);
            fs::write(&path, value.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod {}", path.display()))?;
            envv.insert(format!("{key}_FILE"), path.display().to_string());
        }
        cleanup_dir = Some(dir.keep());
    }
    child.env_clear();
    child.envs(envv);
    let status = child.status().context("run child command")?;
    if let Some(dir) = cleanup_dir {
        let _ = fs::remove_dir_all(dir);
    }
    if status.success() {
        Ok(())
    } else {
        bail!("child command failed with status {}", status);
    }
}

fn sanitized_child_env(current: Vec<(String, String)>) -> BTreeMap<String, String> {
    current
        .into_iter()
        .filter(|(key, _)| {
            key != "FORT_TOKEN"
                && key != "FORT_REFRESH_TOKEN"
                && key != "FORT_BOOTSTRAP_TOKEN_FILE"
                && key != "FORT_TOKEN_FILE"
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_value_file_requires_a_strict_nonempty_secret_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("value");
        fs::write(&path, "from-file\n").expect("write value");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod value");
        let args = SetArgs {
            repo: "example".to_string(),
            env: "dev".to_string(),
            key: "TOKEN".to_string(),
            value: None,
            value_file: Some(path.display().to_string()),
            cas_version: 0,
        };

        assert_eq!(resolve_set_value(&args).expect("value file"), "from-file");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod value");
        assert!(
            resolve_set_value(&args)
                .expect_err("open permissions must fail")
                .to_string()
                .contains("read --value-file")
        );
    }

    #[test]
    fn set_rejects_value_and_value_file_together() {
        let result = FortCli::try_parse_from([
            "fort",
            "set",
            "--repo",
            "example",
            "--env",
            "dev",
            "--key",
            "TOKEN",
            "--value",
            "on-argv",
            "--value-file",
            "/run/secrets/token",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn npm_token_spec_requires_explicit_access_surface() {
        let args = npm_args();
        let error = NpmTokenSpec::from_args(&args).expect_err("missing access surface");
        assert!(
            error
                .to_string()
                .contains("--package, --scope, --org, or explicit --all-packages")
        );
    }

    #[test]
    fn npm_token_spec_caps_read_write_expiry_to_ninety_days() {
        let mut args = npm_args();
        args.all_packages = true;
        args.expires_days = 91;
        let error = NpmTokenSpec::from_args(&args).expect_err("expiry should fail");
        assert!(
            error
                .to_string()
                .contains("read-write token expiration cannot exceed 90 days")
        );
    }

    #[test]
    fn npm_token_spec_rejects_invalid_permission() {
        let mut args = npm_args();
        args.packages = vec!["pkg".to_string()];
        args.packages_permission = "read".to_string();
        let error = NpmTokenSpec::from_args(&args).expect_err("invalid permission");
        assert!(
            error
                .to_string()
                .contains("npm permission must be read-only, read-write, or no-access")
        );
    }

    #[test]
    fn npm_token_spec_rejects_no_access_permission_with_packages_or_scopes() {
        let mut args = npm_args();
        args.packages_permission = "no-access".to_string();
        args.packages = vec!["pkg".to_string()];
        let error = NpmTokenSpec::from_args(&args).expect_err("no-access package should fail");
        assert!(
            error
                .to_string()
                .contains("packages/scopes were provided but --packages-permission is no-access")
        );

        let mut args = npm_args();
        args.packages_permission = "no-access".to_string();
        args.scopes = vec!["@org".to_string()];
        let error = NpmTokenSpec::from_args(&args).expect_err("no-access scope should fail");
        assert!(
            error
                .to_string()
                .contains("packages/scopes were provided but --packages-permission is no-access")
        );
    }

    #[test]
    fn npm_token_spec_rejects_org_no_access_with_orgs() {
        let mut args = npm_args();
        args.orgs_permission = "no-access".to_string();
        args.orgs = vec!["org".to_string()];
        let error = NpmTokenSpec::from_args(&args).expect_err("no-access org should fail");
        assert!(
            error
                .to_string()
                .contains("orgs were provided but --orgs-permission is no-access")
        );
    }

    #[test]
    fn npm_token_spec_rejects_all_packages_with_explicit_packages() {
        let mut args = npm_args();
        args.all_packages = true;
        args.packages = vec!["pkg".to_string()];
        args.orgs = vec!["org".to_string()];
        let error = NpmTokenSpec::from_args(&args).expect_err("all packages conflict");
        assert!(
            error
                .to_string()
                .contains("use either --all-packages or explicit --package values, not both")
        );
    }

    #[test]
    fn npm_token_spec_builds_granular_create_body() {
        let mut args = npm_args();
        args.packages = vec!["svelta-blog".to_string(), "svelta-docs".to_string()];
        args.scopes = vec!["@svelta".to_string()];
        args.cidr = vec!["203.0.113.10/32".to_string()];
        args.bypass_2fa = true;
        let spec = NpmTokenSpec::from_args(&args).expect("spec");
        let body = spec.create_body(Some("secret-password"));

        assert_eq!(body["password"], "secret-password");
        assert_eq!(body["name"], "fort-rotation-test");
        assert_eq!(body["packages"][0], "svelta-blog");
        assert_eq!(body["scopes"][0], "@svelta");
        assert_eq!(body["cidr"][0], "203.0.113.10/32");
        assert_eq!(body["packages_and_scopes_permission"], "read-write");
        assert_eq!(body["bypass_2fa"], true);
    }

    #[test]
    fn npm_token_spec_builds_passwordless_create_body() {
        let mut args = npm_args();
        args.packages = vec!["svelta-blog".to_string()];
        let spec = NpmTokenSpec::from_args(&args).expect("spec");
        let body = spec.create_body(None);

        assert!(body.get("password").is_none());
    }

    #[test]
    fn redacts_secret_without_disclosing_full_token() {
        assert_eq!(
            redact_secret("npm_abcdefghijklmnopqrstuvwxyz0123456789"),
            "npm_abcd...6789"
        );
        assert_eq!(redact_secret("short"), "shor...");
    }

    #[test]
    fn github_secret_name_is_required() {
        let error = validate_github_secret_name("").expect_err("secret name required");
        assert!(error.to_string().contains("GitHub secret name is required"));
    }

    #[test]
    fn github_secret_name_is_restricted() {
        let error = validate_github_secret_name("npm-token").expect_err("bad charset");
        assert!(
            error
                .to_string()
                .contains("GitHub secret name must contain only A-Z, 0-9, and _")
        );
        let error = validate_github_secret_name("GITHUB_TOKEN").expect_err("github prefix");
        assert!(
            error
                .to_string()
                .contains("GitHub secret name must not start with GITHUB_")
        );
    }

    #[test]
    fn github_actions_args_require_token_key_for_repos() {
        let mut args = npm_args();
        args.packages = vec!["pkg".to_string()];
        args.github_actions_repos = vec!["owner/repo".to_string()];
        let error =
            GitHubActionsSecretSink::from_args(&args).expect_err("missing github token key");
        assert!(
            error
                .to_string()
                .contains("--github-token-key is required with --github-actions-repo")
        );
    }

    #[test]
    fn github_actions_args_require_repo_and_env_together() {
        let mut args = npm_args();
        args.packages = vec!["pkg".to_string()];
        args.github_actions_repos = vec!["owner/repo".to_string()];
        args.github_token_key = Some("TOKEN_KEY".to_string());
        args.github_token_repo = Some("safe".to_string());
        let error = GitHubActionsSecretSink::from_args(&args).expect_err("bad repo/env pair");
        assert!(
            error
                .to_string()
                .contains("--github-token-repo and --github-token-env must be provided together")
        );

        let mut args = npm_args();
        args.packages = vec!["pkg".to_string()];
        args.github_actions_repos = vec!["owner/repo".to_string()];
        args.github_token_key = Some("TOKEN_KEY".to_string());
        args.github_token_env = Some("prod".to_string());
        let error = GitHubActionsSecretSink::from_args(&args).expect_err("bad repo/env pair2");
        assert!(
            error
                .to_string()
                .contains("--github-token-repo and --github-token-env must be provided together")
        );
    }

    #[test]
    fn github_repo_ref_requires_owner_and_repo_form() {
        assert!(GitHubRepoRef::parse("owner").is_err());
        assert!(GitHubRepoRef::parse("owner/repo/extra").is_err());
        let parsed = GitHubRepoRef::parse("owner/repo").expect("valid repo");
        assert_eq!(parsed.owner, "owner");
        assert_eq!(parsed.name, "repo");
    }

    #[test]
    fn managed_token_refresh_decision_follows_jwt_expiry() {
        let now = Utc::now().timestamp();
        assert!(token_needs_refresh(&test_jwt(Some(now - 60))));
        assert!(token_needs_refresh(&test_jwt(Some(now + 10))));
        assert!(!token_needs_refresh(&test_jwt(Some(now + 3600))));
    }

    #[test]
    fn managed_token_refresh_decision_refreshes_unparseable_tokens() {
        assert!(token_needs_refresh(&test_jwt(None)));
        for bad in ["", "invalid-token", "a.b", "a.b.c.d", "...", " . . "] {
            assert!(token_needs_refresh(bad), "{bad:?} must trigger refresh");
        }
    }

    fn test_jwt(exp: Option<i64>) -> String {
        let payload = match exp {
            Some(exp) => format!(r#"{{"exp":{exp}}}"#),
            None => r#"{"sub":"test"}"#.to_string(),
        };
        format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload))
    }

    fn npm_args() -> NpmRotateArgs {
        NpmRotateArgs {
            repo: "svelta-blog".to_string(),
            env: "prod".to_string(),
            token_key: "NPM_TOKEN".to_string(),
            management_token_key: Some("NPM_MANAGEMENT_TOKEN".to_string()),
            password_key: Some("NPM_PASSWORD".to_string()),
            otp_file: Some("/tmp/npm-otp".to_string()),
            revoke_otp_file: None,
            name: "fort-rotation-test".to_string(),
            description: "test token".to_string(),
            expires_days: 90,
            packages: Vec::new(),
            scopes: Vec::new(),
            orgs: Vec::new(),
            cidr: Vec::new(),
            packages_permission: "read-write".to_string(),
            orgs_permission: "no-access".to_string(),
            all_packages: false,
            bypass_2fa: false,
            revoke_old: false,
            dry_run: false,
            registry: "https://registry.npmjs.org".to_string(),
            github_actions_repos: Vec::new(),
            github_secret_name: String::new(),
            github_token_key: None,
            github_token_repo: None,
            github_token_env: None,
            github_api_base: "https://api.github.com".to_string(),
        }
    }
}
