use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
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
        let mut out = json!({
            "host": self.host,
            "health_status": health_status,
            "health": health,
            "ready_status": ready_status,
            "ready": ready
        });
        if !self.token.is_empty() {
            if let Ok((status, whoami)) =
                self.api_request(Method::GET, "/v1/auth/whoami", None, true)
            {
                out["whoami_status"] = json!(status);
                out["whoami"] = whoami;
            }
        }
        if self.json {
            print_json(&out)
        } else {
            println!("host: {}", self.host);
            println!("health: {}", health_status);
            println!("ready: {}", ready_status);
            if out.get("whoami").is_some() {
                println!("auth: ok ({})", out["whoami"]);
            }
            Ok(())
        }
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
                let refresh_token = read_secret_file(&args.refresh_token_file)?;
                let out_path = args
                    .refresh_token_out
                    .unwrap_or_else(|| args.refresh_token_file.clone());
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

fn parse_duration_seconds(raw: &str, fallback: Duration) -> Result<i64> {
    if raw.trim().is_empty() {
        return Ok(fallback.as_secs() as i64);
    }
    if let Ok(seconds) = raw.trim().parse::<i64>() {
        if seconds > 0 {
            return Ok(seconds);
        }
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
        .map(|name| {
            Operation::from_str(&name).ok_or_else(|| anyhow::anyhow!("invalid op {}", name))
        })
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
