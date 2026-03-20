use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    Workload,
    User,
    Ci,
}

impl AgentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::User => "user",
            Self::Ci => "ci",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Get,
    Set,
    Run,
    List,
    BatchGet,
    #[serde(rename = "*")]
    Any,
}

impl Operation {
    pub fn normalize(self) -> Self {
        match self {
            Self::BatchGet => Self::Get,
            other => other,
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "get" => Some(Self::Get),
            "set" => Some(Self::Set),
            "run" => Some(Self::Run),
            "list" => Some(Self::List),
            "batch-get" => Some(Self::BatchGet),
            "*" => Some(Self::Any),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Set => "set",
            Self::Run => "run",
            Self::List => "list",
            Self::BatchGet => "batch-get",
            Self::Any => "*",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Agent {
    pub id: String,
    #[serde(rename = "type")]
    pub agent_type: AgentType,
    pub status: AgentStatus,
    pub credential_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Binding {
    pub repo: String,
    pub env: String,
    pub ops: Vec<Operation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Policy {
    pub agent_id: String,
    pub bindings: Vec<Binding>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenRecord {
    pub jti: String,
    pub agent_id: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshSession {
    pub id: String,
    pub agent_id: String,
    pub audience: String,
    pub access_ttl_seconds: i64,
    pub refresh_token_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous_token_hash: String,
    pub refresh_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunSession {
    pub id: String,
    pub agent_id: String,
    pub repo: String,
    pub env: String,
    pub keys: Vec<String>,
    pub mode: String,
    pub one_time_token: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub materialized: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub id: String,
    pub agent_id: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repo: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub env: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub created_at: DateTime<Utc>,
}
