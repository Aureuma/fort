use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Agent, AgentStatus, AgentType, AuditEvent, Binding, Operation, Policy, RefreshSession,
    RunSession, TokenRecord,
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("invalid")]
    Invalid,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PersistentState {
    #[serde(default)]
    agents: BTreeMap<String, Agent>,
    #[serde(default)]
    policies: BTreeMap<String, Policy>,
    #[serde(default)]
    tokens: BTreeMap<String, TokenRecord>,
    #[serde(default)]
    refresh_sessions: BTreeMap<String, RefreshSession>,
    #[serde(default)]
    sessions: BTreeMap<String, RunSession>,
    #[serde(default)]
    audit: Vec<AuditEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DiskRevision {
    exists: bool,
    modified: Option<SystemTime>,
    len: u64,
}

#[derive(Debug)]
pub struct Store {
    path: Option<PathBuf>,
    state: RwLock<PersistentState>,
    disk_revision: RwLock<Option<DiskRevision>>,
}

impl Store {
    pub fn new(path: &str) -> Result<Self> {
        let path = path.trim();
        let resolved = if path.is_empty() {
            None
        } else {
            Some(PathBuf::from(path))
        };
        let state = resolved
            .as_deref()
            .map(Self::load_state_from_path)
            .transpose()?
            .unwrap_or_default();
        let disk_revision = resolved
            .as_deref()
            .map(Self::read_disk_revision)
            .transpose()?;
        Ok(Self {
            path: resolved,
            state: RwLock::new(state),
            disk_revision: RwLock::new(disk_revision),
        })
    }

    fn load_state_from_path(path: &Path) -> Result<PersistentState> {
        if !path.exists() {
            return Ok(PersistentState::default());
        }
        let raw =
            fs::read_to_string(path).with_context(|| format!("read state {}", path.display()))?;
        if raw.trim().is_empty() {
            Ok(PersistentState::default())
        } else {
            serde_json::from_str(&raw).context("decode state")
        }
    }

    fn read_disk_revision(path: &Path) -> Result<DiskRevision> {
        match fs::metadata(path) {
            Ok(metadata) => Ok(DiskRevision {
                exists: true,
                modified: metadata.modified().ok(),
                len: metadata.len(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DiskRevision {
                exists: false,
                modified: None,
                len: 0,
            }),
            Err(error) => Err(error).with_context(|| format!("stat state {}", path.display())),
        }
    }

    fn refresh_from_disk_if_stale(&self) -> Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let next_revision = Self::read_disk_revision(path)?;
        {
            let loaded = self
                .disk_revision
                .read()
                .expect("store revision lock poisoned");
            if loaded.as_ref() == Some(&next_revision) {
                return Ok(());
            }
        }
        let next_state = Self::load_state_from_path(path)?;
        {
            let mut state = self.state.write().expect("store lock poisoned");
            *state = next_state;
        }
        let mut revision = self
            .disk_revision
            .write()
            .expect("store revision lock poisoned");
        *revision = Some(next_revision);
        Ok(())
    }

    fn persist_locked(&self, state: &PersistentState) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(state)?;
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        fs::write(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
        let next_revision = Self::read_disk_revision(path)?;
        let mut revision = self
            .disk_revision
            .write()
            .expect("store revision lock poisoned");
        *revision = Some(next_revision);
        Ok(())
    }

    pub fn create_agent(
        &self,
        id: &str,
        agent_type: Option<AgentType>,
        status: Option<AgentStatus>,
        now: DateTime<Utc>,
    ) -> Result<Agent, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let id = id.trim();
        if id.is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        if state.agents.contains_key(id) {
            return Err(StoreError::Conflict);
        }
        let agent = Agent {
            id: id.to_string(),
            agent_type: agent_type.unwrap_or(AgentType::Workload),
            status: status.unwrap_or(AgentStatus::Active),
            credential_version: 1,
            created_at: now,
            updated_at: now,
        };
        state.agents.insert(id.to_string(), agent.clone());
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(agent)
    }

    pub fn get_agent(&self, id: &str) -> Result<Agent, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        self.state
            .read()
            .expect("store lock poisoned")
            .agents
            .get(id.trim())
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    pub fn list_agents(
        &self,
        filter_type: Option<AgentType>,
        filter_status: Option<AgentStatus>,
    ) -> Vec<Agent> {
        let _ = self.refresh_from_disk_if_stale();
        let mut out: Vec<_> = self
            .state
            .read()
            .expect("store lock poisoned")
            .agents
            .values()
            .filter(|agent| {
                filter_type
                    .as_ref()
                    .is_none_or(|expected| &agent.agent_type == expected)
            })
            .filter(|agent| {
                filter_status
                    .as_ref()
                    .is_none_or(|expected| &agent.status == expected)
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn set_agent_status(
        &self,
        id: &str,
        status: AgentStatus,
        now: DateTime<Utc>,
    ) -> Result<Agent, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let agent = state
            .agents
            .get_mut(id.trim())
            .ok_or(StoreError::NotFound)?;
        agent.status = status;
        agent.updated_at = now;
        let out = agent.clone();
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(out)
    }

    pub fn rotate_agent_credentials(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<(Agent, usize, usize), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let agent = state
            .agents
            .get_mut(id.trim())
            .ok_or(StoreError::NotFound)?;
        agent.credential_version += 1;
        agent.updated_at = now;
        let agent_snapshot = agent.clone();
        let mut revoked_tokens = 0usize;
        for token in state.tokens.values_mut() {
            if token.agent_id == id.trim() && token.revoked_at.is_none() {
                token.revoked_at = Some(now);
                token.reason = "agent_credentials_rotated".to_string();
                revoked_tokens += 1;
            }
        }
        let mut revoked_sessions = 0usize;
        for session in state.refresh_sessions.values_mut() {
            if session.agent_id == id.trim() && session.revoked_at.is_none() {
                session.revoked_at = Some(now);
                session.updated_at = now;
                revoked_sessions += 1;
            }
        }
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok((agent_snapshot, revoked_tokens, revoked_sessions))
    }

    pub fn remove_agent(&self, id: &str) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let id = id.trim();
        let mut state = self.state.write().expect("store lock poisoned");
        if state.agents.remove(id).is_none() {
            return Err(StoreError::NotFound);
        }
        state.policies.remove(id);
        state.tokens.retain(|_, token| token.agent_id != id);
        state
            .refresh_sessions
            .retain(|_, session| session.agent_id != id);
        state.sessions.retain(|_, session| session.agent_id != id);
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn get_policy(&self, agent_id: &str) -> Result<Policy, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        Ok(self
            .state
            .read()
            .expect("store lock poisoned")
            .policies
            .get(agent_id.trim())
            .cloned()
            .unwrap_or(Policy {
                agent_id: agent_id.trim().to_string(),
                bindings: Vec::new(),
                updated_at: Utc::now(),
            }))
    }

    fn normalize_ops(ops: &[Operation]) -> Vec<Operation> {
        let mut seen = BTreeSet::new();
        for op in ops {
            let normalized = op.clone().normalize();
            if matches!(normalized, Operation::Any) {
                return vec![Operation::Any];
            }
            seen.insert(normalized.as_str().to_string());
        }
        seen.into_iter()
            .filter_map(|name| Operation::parse(&name))
            .collect()
    }

    fn normalize_binding(binding: &Binding) -> Option<Binding> {
        let repo = binding.repo.trim().to_string();
        let env = binding.env.trim().to_string();
        let ops = Self::normalize_ops(&binding.ops);
        if repo.is_empty() || env.is_empty() || ops.is_empty() {
            None
        } else {
            Some(Binding { repo, env, ops })
        }
    }

    fn binding_key(binding: &Binding) -> String {
        let ops = binding
            .ops
            .iter()
            .map(Operation::as_str)
            .collect::<Vec<_>>()
            .join(",");
        format!("{}|{}|{}", binding.repo, binding.env, ops)
    }

    pub fn set_policy(
        &self,
        agent_id: &str,
        bindings: &[Binding],
        now: DateTime<Utc>,
    ) -> Result<Policy, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        if !state.agents.contains_key(agent_id.trim()) {
            return Err(StoreError::NotFound);
        }
        let mut unique = BTreeMap::new();
        for binding in bindings.iter().filter_map(Self::normalize_binding) {
            unique.insert(Self::binding_key(&binding), binding);
        }
        let bindings = unique.into_values().collect::<Vec<_>>();
        let policy = Policy {
            agent_id: agent_id.trim().to_string(),
            bindings,
            updated_at: now,
        };
        state
            .policies
            .insert(agent_id.trim().to_string(), policy.clone());
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(policy)
    }

    pub fn add_binding(
        &self,
        agent_id: &str,
        binding: &Binding,
        now: DateTime<Utc>,
    ) -> Result<Policy, StoreError> {
        let normalized = Self::normalize_binding(binding).ok_or(StoreError::Invalid)?;
        let mut existing = self.get_policy(agent_id)?;
        if existing.bindings.iter().any(|item| item == &normalized) {
            return Ok(existing);
        }
        existing.bindings.push(normalized);
        self.set_policy(agent_id, &existing.bindings, now)
    }

    pub fn remove_binding(
        &self,
        agent_id: &str,
        binding: &Binding,
        now: DateTime<Utc>,
    ) -> Result<Policy, StoreError> {
        let normalized = Self::normalize_binding(binding).ok_or(StoreError::Invalid)?;
        let existing = self.get_policy(agent_id)?;
        let filtered = existing
            .bindings
            .into_iter()
            .filter(|item| item != &normalized)
            .collect::<Vec<_>>();
        self.set_policy(agent_id, &filtered, now)
    }

    pub fn check_permission(
        &self,
        agent_id: &str,
        repo: &str,
        env: &str,
        op: Operation,
    ) -> (bool, &'static str) {
        let _ = self.refresh_from_disk_if_stale();
        let agent = match self.get_agent(agent_id) {
            Ok(agent) => agent,
            Err(_) => return (false, "agent_not_found"),
        };
        if agent.status != AgentStatus::Active {
            return (false, "agent_disabled");
        }
        let normalized = op.normalize();
        let policy = match self.get_policy(agent_id) {
            Ok(policy) => policy,
            Err(_) => return (false, "no_matching_binding"),
        };
        for binding in policy.bindings {
            let repo_match = binding.repo == "*" || binding.repo == repo.trim();
            let env_match = binding.env == "*" || binding.env == env.trim();
            if !repo_match || !env_match {
                continue;
            }
            if binding.ops.iter().any(|allowed| {
                *allowed == Operation::Any || allowed.clone().normalize() == normalized
            }) {
                return (true, "allowed");
            }
        }
        (false, "no_matching_binding")
    }

    pub fn put_token(&self, record: TokenRecord) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        if record.jti.trim().is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        state.tokens.insert(record.jti.clone(), record);
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn get_token(&self, jti: &str) -> Result<TokenRecord, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        self.state
            .read()
            .expect("store lock poisoned")
            .tokens
            .get(jti.trim())
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    pub fn list_tokens(
        &self,
        agent_id: &str,
        active_only: bool,
        now: DateTime<Utc>,
    ) -> Vec<TokenRecord> {
        let _ = self.refresh_from_disk_if_stale();
        let mut out: Vec<_> = self
            .state
            .read()
            .expect("store lock poisoned")
            .tokens
            .values()
            .filter(|token| agent_id.trim().is_empty() || token.agent_id == agent_id.trim())
            .filter(|token| !active_only || (token.revoked_at.is_none() && now <= token.expires_at))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.issued_at
                .cmp(&a.issued_at)
                .then_with(|| a.jti.cmp(&b.jti))
        });
        out
    }

    pub fn revoke_token(
        &self,
        jti: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<TokenRecord, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let token = state
            .tokens
            .get_mut(jti.trim())
            .ok_or(StoreError::NotFound)?;
        if token.revoked_at.is_none() {
            token.revoked_at = Some(now);
        }
        token.reason = reason.trim().to_string();
        let out = token.clone();
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(out)
    }

    pub fn revoke_active_tokens_for_agent(
        &self,
        agent_id: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        if agent_id.trim().is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        let mut revoked = 0usize;
        for token in state.tokens.values_mut() {
            if token.agent_id != agent_id.trim() {
                continue;
            }
            if token.revoked_at.is_some() || now > token.expires_at {
                continue;
            }
            token.revoked_at = Some(now);
            token.reason = reason.trim().to_string();
            revoked += 1;
        }
        if revoked > 0 {
            self.persist_locked(&state)
                .map_err(|_| StoreError::Invalid)?;
        }
        Ok(revoked)
    }

    pub fn put_refresh_session(&self, session: RefreshSession) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        if session.id.trim().is_empty()
            || session.agent_id.trim().is_empty()
            || session.refresh_token_hash.trim().is_empty()
        {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        if state.refresh_sessions.contains_key(&session.id) {
            return Err(StoreError::Conflict);
        }
        state.refresh_sessions.insert(session.id.clone(), session);
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn get_refresh_session(&self, id: &str) -> Result<RefreshSession, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        self.state
            .read()
            .expect("store lock poisoned")
            .refresh_sessions
            .get(id.trim())
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    pub fn get_refresh_session_by_any_token(
        &self,
        hash: &str,
    ) -> Result<(RefreshSession, bool), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let state = self.state.read().expect("store lock poisoned");
        for session in state.refresh_sessions.values() {
            if session.refresh_token_hash == hash {
                return Ok((session.clone(), false));
            }
        }
        for session in state.refresh_sessions.values() {
            if session.previous_token_hash == hash {
                return Ok((session.clone(), true));
            }
        }
        Err(StoreError::NotFound)
    }

    pub fn rotate_refresh_session_token(
        &self,
        id: &str,
        next_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<RefreshSession, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let session = state
            .refresh_sessions
            .get_mut(id.trim())
            .ok_or(StoreError::NotFound)?;
        session.previous_token_hash = session.refresh_token_hash.clone();
        session.refresh_token_hash = next_hash.trim().to_string();
        session.updated_at = now;
        let out = session.clone();
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(out)
    }

    pub fn revoke_refresh_session(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<RefreshSession, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let session = state
            .refresh_sessions
            .get_mut(id.trim())
            .ok_or(StoreError::NotFound)?;
        if session.revoked_at.is_none() {
            session.revoked_at = Some(now);
            session.updated_at = now;
        }
        let out = session.clone();
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(out)
    }

    pub fn revoke_active_refresh_sessions_for_agent(
        &self,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        if agent_id.trim().is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        let mut revoked = 0usize;
        for session in state.refresh_sessions.values_mut() {
            if session.agent_id != agent_id.trim() {
                continue;
            }
            if session.revoked_at.is_some() || now > session.refresh_expires_at {
                continue;
            }
            session.revoked_at = Some(now);
            session.updated_at = now;
            revoked += 1;
        }
        if revoked > 0 {
            self.persist_locked(&state)
                .map_err(|_| StoreError::Invalid)?;
        }
        Ok(revoked)
    }

    pub fn put_session(&self, session: RunSession) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        if session.id.trim().is_empty() {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.write().expect("store lock poisoned");
        if state.sessions.contains_key(&session.id) {
            return Err(StoreError::Conflict);
        }
        state.sessions.insert(session.id.clone(), session);
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn get_session(&self, id: &str) -> Result<RunSession, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        self.state
            .read()
            .expect("store lock poisoned")
            .sessions
            .get(id.trim())
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    pub fn mark_session_used(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<RunSession, StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        let session = state
            .sessions
            .get_mut(id.trim())
            .ok_or(StoreError::NotFound)?;
        if session.materialized {
            return Err(StoreError::Conflict);
        }
        session.materialized = true;
        session.used_at = Some(now);
        let out = session.clone();
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(out)
    }

    pub fn close_session(&self, id: &str) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        if state.sessions.remove(id.trim()).is_none() {
            return Err(StoreError::NotFound);
        }
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn add_audit(&self, mut event: AuditEvent) -> Result<(), StoreError> {
        self.refresh_from_disk_if_stale()
            .map_err(|_| StoreError::Invalid)?;
        let mut state = self.state.write().expect("store lock poisoned");
        if event.created_at.timestamp() == 0 {
            event.created_at = Utc::now();
        }
        state.audit.push(event);
        if state.audit.len() > 5000 {
            let drain = state.audit.len() - 5000;
            state.audit.drain(0..drain);
        }
        self.persist_locked(&state)
            .map_err(|_| StoreError::Invalid)?;
        Ok(())
    }

    pub fn list_audit(&self, limit: usize) -> Vec<AuditEvent> {
        let _ = self.refresh_from_disk_if_stale();
        let state = self.state.read().expect("store lock poisoned");
        let actual = if limit == 0 || limit > state.audit.len() {
            state.audit.len()
        } else {
            limit
        };
        state.audit.iter().rev().take(actual).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    #[test]
    fn store_reads_external_agent_changes_from_disk() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("state.json");
        let store_a = Store::new(path.to_str().expect("path")).expect("store a");
        let store_b = Store::new(path.to_str().expect("path")).expect("store b");
        let now = Utc::now();

        store_a
            .create_agent(
                "agent-alpha",
                Some(AgentType::Workload),
                Some(AgentStatus::Active),
                now,
            )
            .expect("create alpha");
        store_b
            .create_agent(
                "agent-beta",
                Some(AgentType::Workload),
                Some(AgentStatus::Active),
                now,
            )
            .expect("create beta");

        let loaded = store_a
            .get_agent("agent-beta")
            .expect("load beta from refreshed disk");
        assert_eq!(loaded.id, "agent-beta");
    }

    #[test]
    fn store_preserves_external_changes_before_writing() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("state.json");
        let store_a = Store::new(path.to_str().expect("path")).expect("store a");
        let store_b = Store::new(path.to_str().expect("path")).expect("store b");
        let now = Utc::now();

        store_a
            .create_agent(
                "agent-alpha",
                Some(AgentType::Workload),
                Some(AgentStatus::Active),
                now,
            )
            .expect("create alpha");
        store_b
            .create_agent(
                "agent-beta",
                Some(AgentType::Workload),
                Some(AgentStatus::Active),
                now,
            )
            .expect("create beta");
        store_a
            .create_agent(
                "agent-gamma",
                Some(AgentType::Workload),
                Some(AgentStatus::Active),
                now,
            )
            .expect("create gamma");

        let store_c = Store::new(path.to_str().expect("path")).expect("store c");
        let agents = store_c.list_agents(None, None);
        let ids = agents.into_iter().map(|agent| agent.id).collect::<Vec<_>>();
        assert_eq!(ids, vec!["agent-alpha", "agent-beta", "agent-gamma"]);
    }
}
