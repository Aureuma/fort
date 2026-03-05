package model

import "time"

type AgentType string

const (
	AgentTypeWorkload AgentType = "workload"
	AgentTypeUser     AgentType = "user"
	AgentTypeCI       AgentType = "ci"
)

type AgentStatus string

const (
	AgentStatusActive   AgentStatus = "active"
	AgentStatusDisabled AgentStatus = "disabled"
)

type Operation string

const (
	OpGet      Operation = "get"
	OpSet      Operation = "set"
	OpRun      Operation = "run"
	OpList     Operation = "list"
	OpBatchGet Operation = "batch-get"
	OpAny      Operation = "*"
)

func NormalizeOperation(op Operation) Operation {
	if op == OpBatchGet {
		return OpGet
	}
	return op
}

func IsSupportedOperation(op Operation) bool {
	switch op {
	case OpGet, OpSet, OpRun, OpList, OpBatchGet, OpAny:
		return true
	default:
		return false
	}
}

type Agent struct {
	ID                string      `json:"id"`
	Type              AgentType   `json:"type"`
	Status            AgentStatus `json:"status"`
	CredentialVersion int64       `json:"credential_version"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
}

type Binding struct {
	Repo string      `json:"repo"`
	Env  string      `json:"env"`
	Ops  []Operation `json:"ops"`
}

type Policy struct {
	AgentID   string    `json:"agent_id"`
	Bindings  []Binding `json:"bindings"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TokenRecord struct {
	JTI       string    `json:"jti"`
	AgentID   string    `json:"agent_id"`
	Audience  string    `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

type RefreshSession struct {
	ID               string    `json:"id"`
	AgentID          string    `json:"agent_id"`
	Audience         string    `json:"audience"`
	AccessTTLSeconds int64     `json:"access_ttl_seconds"`
	RefreshTokenHash string    `json:"refresh_token_hash"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
}

type RunSession struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Repo         string    `json:"repo"`
	Env          string    `json:"env"`
	Keys         []string  `json:"keys"`
	Mode         string    `json:"mode"`
	OneTimeToken string    `json:"one_time_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UsedAt       time.Time `json:"used_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Materialized bool      `json:"materialized"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Action    string    `json:"action"`
	Repo      string    `json:"repo,omitempty"`
	Env       string    `json:"env,omitempty"`
	Key       string    `json:"key,omitempty"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
