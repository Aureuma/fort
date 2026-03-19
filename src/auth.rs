use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{Agent, AgentStatus, RefreshSession, TokenRecord};
use crate::store::{Store, StoreError};

pub const BREAKGLASS_ADMIN_AGENT_ID: &str = "fort-breakglass-admin";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Claims {
    pub agent_id: String,
    #[serde(rename = "type")]
    pub claim_type: String,
    pub credential_version: i64,
    pub jti: String,
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("refresh token reuse detected")]
    RefreshReuseDetected,
    #[error("internal")]
    Internal,
}

#[derive(Clone)]
pub struct Manager {
    pub signing_key: Vec<u8>,
    pub issuer: Option<String>,
    pub store: Arc<Store>,
}

impl Manager {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn issuer(&self) -> String {
        self.issuer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("fortd")
            .to_string()
    }

    pub fn issue(
        &self,
        agent: &Agent,
        ttl: Duration,
        audience: &str,
    ) -> Result<(String, TokenRecord), AuthError> {
        self.issue_internal(agent, ttl, audience, true)
    }

    fn issue_internal(
        &self,
        agent: &Agent,
        ttl: Duration,
        audience: &str,
        revoke_breakglass_artifacts: bool,
    ) -> Result<(String, TokenRecord), AuthError> {
        let ttl = if ttl.is_zero() {
            Duration::from_secs(15 * 60)
        } else {
            ttl
        };
        let audience = if audience.trim().is_empty() {
            "fort-api"
        } else {
            audience.trim()
        };
        let now = self.now();
        if revoke_breakglass_artifacts && agent.id == BREAKGLASS_ADMIN_AGENT_ID {
            self.store
                .revoke_active_tokens_for_agent(&agent.id, "breakglass_reissued", now)
                .map_err(|_| AuthError::Internal)?;
            self.store
                .revoke_active_refresh_sessions_for_agent(&agent.id, now)
                .map_err(|_| AuthError::Internal)?;
        }
        let exp =
            now + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::minutes(15));
        let jti = random_hex(16).map_err(|_| AuthError::Internal)?;
        let claims = Claims {
            agent_id: agent.id.clone(),
            claim_type: agent.agent_type.as_str().to_string(),
            credential_version: agent.credential_version,
            jti: jti.clone(),
            iss: self.issuer(),
            sub: agent.id.clone(),
            aud: vec![audience.to_string()],
            iat: now.timestamp(),
            exp: exp.timestamp(),
            nbf: (now - chrono::Duration::seconds(5)).timestamp(),
        };
        let header = Header::new(Algorithm::HS256);
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(&self.signing_key),
        )
        .map_err(|_| AuthError::Internal)?;
        let record = TokenRecord {
            jti,
            agent_id: agent.id.clone(),
            audience: audience.to_string(),
            issued_at: now,
            expires_at: exp,
            revoked_at: None,
            reason: String::new(),
        };
        self.store
            .put_token(record.clone())
            .map_err(|_| AuthError::Internal)?;
        Ok((token, record))
    }

    pub fn open_refresh_session(
        &self,
        agent: &Agent,
        access_ttl: Duration,
        refresh_ttl: Duration,
        audience: &str,
    ) -> Result<(String, TokenRecord, RefreshSession, String), AuthError> {
        let access_ttl = if access_ttl.is_zero() {
            Duration::from_secs(15 * 60)
        } else {
            access_ttl
        };
        let refresh_ttl = if refresh_ttl.is_zero() {
            Duration::from_secs(24 * 60 * 60)
        } else {
            refresh_ttl
        };
        let audience = if audience.trim().is_empty() {
            "fort-api"
        } else {
            audience.trim()
        };
        let now = self.now();
        self.store
            .revoke_active_refresh_sessions_for_agent(&agent.id, now)
            .map_err(|_| AuthError::Internal)?;
        let (access_token, record) = self.issue(agent, access_ttl, audience)?;
        let session_id = random_id("rfs_", 12).map_err(|_| AuthError::Internal)?;
        let refresh_token = random_id("rft_", 24).map_err(|_| AuthError::Internal)?;
        let session = RefreshSession {
            id: session_id,
            agent_id: agent.id.clone(),
            audience: audience.to_string(),
            access_ttl_seconds: access_ttl.as_secs() as i64,
            refresh_token_hash: hash_refresh_token(&refresh_token),
            previous_token_hash: String::new(),
            refresh_expires_at: now
                + chrono::Duration::from_std(refresh_ttl)
                    .unwrap_or_else(|_| chrono::Duration::hours(24)),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        };
        self.store
            .put_refresh_session(session.clone())
            .map_err(|_| AuthError::Internal)?;
        Ok((access_token, record, session, refresh_token))
    }

    pub fn parse(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "sub", "aud"]);
        let data = decode::<Claims>(
            token.trim(),
            &DecodingKey::from_secret(&self.signing_key),
            &validation,
        )
        .map_err(|_| AuthError::Unauthorized)?;
        let claims = data.claims;
        if claims.jti.trim().is_empty()
            || claims.agent_id.trim().is_empty()
            || claims.credential_version <= 0
            || claims.sub.trim() != claims.agent_id.trim()
            || claims.iss.trim() != self.issuer()
            || claims.aud.is_empty()
        {
            return Err(AuthError::Unauthorized);
        }
        let record = self
            .store
            .get_token(&claims.jti)
            .map_err(|_| AuthError::Unauthorized)?;
        if record.agent_id != claims.agent_id
            || !claims.aud.iter().any(|aud| aud.trim() == record.audience)
        {
            return Err(AuthError::Unauthorized);
        }
        let now = self.now();
        if record.revoked_at.is_some() || now > record.expires_at {
            return Err(AuthError::Unauthorized);
        }
        let agent = self
            .store
            .get_agent(&claims.agent_id)
            .map_err(|_| AuthError::Unauthorized)?;
        if agent.status != AgentStatus::Active
            || agent.credential_version != claims.credential_version
        {
            return Err(AuthError::Unauthorized);
        }
        Ok(claims)
    }

    pub fn refresh_by_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, TokenRecord, RefreshSession, String), AuthError> {
        let hash = hash_refresh_token(refresh_token);
        let (session, reused_previous) = self
            .store
            .get_refresh_session_by_any_token(&hash)
            .map_err(|_| AuthError::Unauthorized)?;
        let now = self.now();
        if reused_previous {
            let _ = self.store.revoke_refresh_session(&session.id, now);
            return Err(AuthError::RefreshReuseDetected);
        }
        if session.revoked_at.is_some() || now > session.refresh_expires_at {
            return Err(AuthError::Unauthorized);
        }
        let agent = self
            .store
            .get_agent(&session.agent_id)
            .map_err(|_| AuthError::Unauthorized)?;
        if agent.status != AgentStatus::Active {
            return Err(AuthError::Unauthorized);
        }
        let access_ttl = Duration::from_secs(session.access_ttl_seconds.max(1) as u64);
        let (access_token, record) =
            self.issue_internal(&agent, access_ttl, &session.audience, false)?;
        let next_refresh_token = random_id("rft_", 24).map_err(|_| AuthError::Internal)?;
        let rotated = self
            .store
            .rotate_refresh_session_token(
                &session.id,
                &hash_refresh_token(&next_refresh_token),
                now,
            )
            .map_err(|_| AuthError::Internal)?;
        Ok((access_token, record, rotated, next_refresh_token))
    }

    pub fn close_refresh_session_by_id(&self, id: &str) -> Result<RefreshSession, AuthError> {
        self.store
            .revoke_refresh_session(id.trim(), self.now())
            .map_err(map_store_err)
    }

    pub fn close_refresh_session_by_token(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshSession, AuthError> {
        let hash = hash_refresh_token(refresh_token);
        let (session, reused_previous) = self
            .store
            .get_refresh_session_by_any_token(&hash)
            .map_err(map_store_err)?;
        if reused_previous {
            return Err(AuthError::Unauthorized);
        }
        self.store
            .revoke_refresh_session(&session.id, self.now())
            .map_err(map_store_err)
    }

    pub fn revoke(&self, jti: &str, reason: &str) -> Result<TokenRecord, AuthError> {
        self.store
            .revoke_token(jti.trim(), reason.trim(), self.now())
            .map_err(map_store_err)
    }

    pub fn list(&self, agent_id: &str, active_only: bool) -> Vec<TokenRecord> {
        self.store.list_tokens(agent_id, active_only, self.now())
    }
}

fn map_store_err(err: StoreError) -> AuthError {
    match err {
        StoreError::NotFound | StoreError::Invalid => AuthError::Unauthorized,
        StoreError::Conflict => AuthError::Internal,
    }
}

pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.trim().as_bytes());
    hex::encode(hasher.finalize())
}

fn random_hex(bytes: usize) -> std::io::Result<String> {
    let mut raw = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    Ok(hex::encode(raw))
}

fn random_id(prefix: &str, bytes: usize) -> std::io::Result<String> {
    Ok(format!("{}{}", prefix, random_hex(bytes)?))
}
