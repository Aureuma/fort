use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
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
#[command(name = "fort")]
pub struct FortCli {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    token_file: Option<String>,
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: FortCommand,
}

#[derive(Subcommand)]
enum FortCommand {
    Version,
    Doctor,
    Auth(AuthCommand),
    Get(GetArgs),
    Set(SetArgs),
    List(ListArgs),
    #[command(name = "batch-get")]
    BatchGet(BatchGetArgs),
    Run(RunArgs),
    Rotate(Box<RotateCommand>),
    Agent(AgentCommand),
}

#[derive(Args)]
struct GetArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    key: String,
    #[arg(long, default_value = "raw")]
    format: String,
}

#[derive(Args)]
struct SetArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    key: String,
    #[arg(long, default_value = "")]
    value: String,
    #[arg(long, default_value_t = 0)]
    cas_version: i64,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long, default_value = "")]
    prefix: String,
}

#[derive(Args)]
struct BatchGetArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    keys: String,
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    keys: String,
    #[arg(long, default_value = "files")]
    mode: String,
    #[arg(long, default_value = "60s")]
    ttl: String,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct RotateCommand {
    #[command(subcommand)]
    command: RotateSubcommand,
}

#[derive(Subcommand)]
enum RotateSubcommand {
    Npm(Box<NpmRotateArgs>),
}

#[derive(Args)]
struct NpmRotateArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    token_key: String,
    #[arg(long)]
    management_token_key: Option<String>,
    #[arg(long)]
    password_key: Option<String>,
    #[arg(long)]
    otp_file: Option<String>,
    #[arg(long)]
    revoke_otp_file: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long, default_value = "")]
    description: String,
    #[arg(long, default_value_t = 90)]
    expires_days: i64,
    #[arg(long = "package")]
    packages: Vec<String>,
    #[arg(long = "scope")]
    scopes: Vec<String>,
    #[arg(long = "org")]
    orgs: Vec<String>,
    #[arg(long = "cidr")]
    cidr: Vec<String>,
    #[arg(long, default_value = "read-write")]
    packages_permission: String,
    #[arg(long, default_value = "no-access")]
    orgs_permission: String,
    #[arg(long, default_value_t = false)]
    all_packages: bool,
    #[arg(long, default_value_t = false)]
    bypass_2fa: bool,
    #[arg(long, default_value_t = false)]
    revoke_old: bool,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[arg(long, default_value = "https://registry.npmjs.org")]
    registry: String,
    #[arg(long = "github-actions-repo")]
    github_actions_repos: Vec<String>,
    #[arg(long, default_value = "")]
    github_secret_name: String,
    #[arg(long)]
    github_token_key: Option<String>,
    #[arg(long)]
    github_token_repo: Option<String>,
    #[arg(long)]
    github_token_env: Option<String>,
    #[arg(long, default_value = "https://api.github.com")]
    github_api_base: String,
}

#[derive(Args)]
struct AuthCommand {
    #[command(subcommand)]
    command: AuthSubcommand,
}

#[derive(Subcommand)]
enum AuthSubcommand {
    Issue(AuthIssueArgs),
    Login(AuthIssueArgs),
    Whoami,
    List(AuthListArgs),
    Revoke(AuthRevokeArgs),
    Session(AuthSessionCommand),
}

#[derive(Args)]
struct AuthIssueArgs {
    #[arg(long)]
    agent: String,
    #[arg(long, default_value = "")]
    ttl: String,
    #[arg(long, default_value = "fort-api")]
    aud: String,
}

#[derive(Args)]
struct AuthListArgs {
    #[arg(long, default_value = "")]
    agent: String,
    #[arg(long, default_value_t = false)]
    active_only: bool,
}

#[derive(Args)]
struct AuthRevokeArgs {
    #[arg(long)]
    jti: String,
    #[arg(long, default_value = "")]
    reason: String,
}

#[derive(Args)]
struct AuthSessionCommand {
    #[command(subcommand)]
    command: AuthSessionSubcommand,
}

#[derive(Subcommand)]
enum AuthSessionSubcommand {
    Open(AuthSessionOpenArgs),
    Refresh(AuthSessionRefreshArgs),
    Close(AuthSessionCloseArgs),
}

#[derive(Args)]
struct AuthSessionOpenArgs {
    #[arg(long)]
    agent: String,
    #[arg(long, default_value = "fort-api")]
    aud: String,
    #[arg(long, default_value = "")]
    access_ttl: String,
    #[arg(long, default_value = "")]
    refresh_ttl: String,
    #[arg(long)]
    refresh_token_out: String,
}

#[derive(Args)]
struct AuthSessionRefreshArgs {
    #[arg(long)]
    refresh_token_file: String,
    #[arg(long)]
    refresh_token_out: Option<String>,
}

#[derive(Args)]
struct AuthSessionCloseArgs {
    #[arg(long, default_value = "")]
    session_id: String,
    #[arg(long)]
    refresh_token_file: Option<String>,
}

#[derive(Args)]
struct AgentCommand {
    #[command(subcommand)]
    command: AgentSubcommand,
}

#[derive(Subcommand)]
enum AgentSubcommand {
    Create(AgentCreateArgs),
    Get(AgentGetArgs),
    List(AgentListArgs),
    SetStatus(AgentSetStatusArgs),
    Rotate(AgentRotateArgs),
    Remove(AgentRemoveArgs),
    Policy(AgentPolicyCommand),
}

#[derive(Args)]
struct AgentCreateArgs {
    #[arg(long)]
    id: String,
    #[arg(long = "type", default_value = "workload")]
    agent_type: String,
    #[arg(long, default_value = "active")]
    status: String,
}

#[derive(Args)]
struct AgentGetArgs {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct AgentListArgs {
    #[arg(long = "type")]
    agent_type: Option<String>,
    #[arg(long)]
    status: Option<String>,
}

#[derive(Args)]
struct AgentSetStatusArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    status: String,
}

#[derive(Args)]
struct AgentRotateArgs {
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct AgentRemoveArgs {
    #[arg(long)]
    id: String,
    #[arg(long, default_value_t = false)]
    force: bool,
}

#[derive(Args)]
struct AgentPolicyCommand {
    #[command(subcommand)]
    command: AgentPolicySubcommand,
}

#[derive(Subcommand)]
enum AgentPolicySubcommand {
    Get(AgentGetArgs),
    Set(AgentPolicySetArgs),
    Add(AgentPolicyAddRemoveArgs),
    Remove(AgentPolicyAddRemoveArgs),
    Check(AgentPolicyCheckArgs),
}

#[derive(Args)]
struct AgentPolicySetArgs {
    #[arg(long)]
    id: String,
    #[arg(long = "bind", required = true)]
    binds: Vec<String>,
    #[arg(long, default_value_t = true)]
    replace: bool,
}

#[derive(Args)]
struct AgentPolicyAddRemoveArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    bind: String,
}

#[derive(Args)]
struct AgentPolicyCheckArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    repo: String,
    #[arg(long)]
    env: String,
    #[arg(long)]
    op: String,
}

pub fn run() -> Result<()> {
    reject_deprecated_token_value_env()?;
    let cli = FortCli::parse();
    let client = Client::new(cli.host, cli.token_file, cli.json)?;
    client.run(cli.command)
}

struct Client {
    host: String,
    token: String,
    json: bool,
    http: HttpClient,
}

impl Client {
    fn new(host: Option<String>, token_file: Option<String>, json: bool) -> Result<Self> {
        let host = resolve_host(host)?;
        let token = resolve_token(token_file)?;
        Ok(Self {
            host,
            token,
            json,
            http: HttpClient::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("build http client")?,
        })
    }

    fn run(&self, command: FortCommand) -> Result<()> {
        match command {
            FortCommand::Version => self.cmd_version(),
            FortCommand::Doctor => self.cmd_doctor(),
            FortCommand::Auth(command) => self.cmd_auth(command.command),
            FortCommand::Get(args) => self.cmd_get(args),
            FortCommand::Set(args) => self.cmd_set(args),
            FortCommand::List(args) => self.cmd_list(args),
            FortCommand::BatchGet(args) => self.cmd_batch_get(args),
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

    fn cmd_version(&self) -> Result<()> {
        if self.json {
            print_json(&json!({ "version": env!("CARGO_PKG_VERSION") }))
        } else {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
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
                guard_codex_profile_refresh_token_rotation(
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
        let (status, response) = self.api_request(
            Method::POST,
            "/v1/secrets/set",
            Some(json!({
                "repo": args.repo,
                "env": args.env,
                "key": args.key,
                "value": args.value,
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

        let old_token = self.get_secret_value(&args.repo, &args.env, &args.token_key)?;
        let management_token = if management_token_key == args.token_key {
            old_token.clone()
        } else {
            self.get_secret_value(&args.repo, &args.env, management_token_key)?
        };
        let password = if let Some(password_key) = args.password_key.as_deref() {
            Some(self.get_secret_value(&args.repo, &args.env, password_key)?)
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
            let github_token = self.get_secret_value(token_repo, token_env, &sink.token_key)?;
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
            "fort host is required (set --host, FORT_HOST, or ~/.si/fort/settings.toml [fort].host)"
        );
    }
    let parsed = Url::parse(candidate.trim())
        .with_context(|| format!("invalid host {}", candidate.trim()))?;
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn resolve_token(flag_token_file: Option<String>) -> Result<String> {
    if let Some(path) = flag_token_file {
        return read_secret_file(&path);
    }
    for path in [
        env::var("FORT_TOKEN_PATH").unwrap_or_default(),
        env::var("FORT_BOOTSTRAP_TOKEN_FILE").unwrap_or_default(),
    ] {
        if path.trim().is_empty() {
            continue;
        }
        if let Ok(token) = read_secret_file(&path) {
            return Ok(token);
        }
    }
    Ok(String::new())
}

fn guard_codex_profile_refresh_token_rotation(
    refresh_token_file: &Path,
    refresh_token_out: &Path,
) -> Result<()> {
    if !is_codex_profile_refresh_token_path(refresh_token_file) {
        return Ok(());
    }
    let refresh_token_file = normalize_path_components(refresh_token_file.to_path_buf());
    let refresh_token_out = normalize_path_components(refresh_token_out.to_path_buf());
    if refresh_token_file != refresh_token_out {
        bail!(
            "refusing to rotate Codex profile Fort refresh token {} into {}; profile refresh tokens must be refreshed in place",
            refresh_token_file.display(),
            refresh_token_out.display()
        );
    }
    Ok(())
}

fn is_codex_profile_refresh_token_path(path: &Path) -> bool {
    let normalized = normalize_path_components(path.to_path_buf());
    let parts = normalized
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    parts.len() >= 6
        && parts[parts.len() - 1] == "refresh.token"
        && parts[parts.len() - 2] == "fort"
        && parts[parts.len() - 4] == "profiles"
        && parts[parts.len() - 5] == "codex"
        && parts[parts.len() - 6] == ".si"
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
        let args = npm_args();
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
