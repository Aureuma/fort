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
	OpGet   Operation = "get"
	OpSet   Operation = "set"
	OpRun   Operation = "run"
	OpList  Operation = "list"
	OpBatch Operation = "batch-get"
)

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

type RunSession struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Repo        string    `json:"repo"`
	Env         string    `json:"env"`
	Keys        []string  `json:"keys"`
	Mode        string    `json:"mode"`
	OneTimeJTI  string    `json:"one_time_jti"`
	ExpiresAt   time.Time `json:"expires_at"`
	UsedAt      time.Time `json:"used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Materialized bool     `json:"materialized"`
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
