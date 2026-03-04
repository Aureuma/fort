package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"fort/internal/model"
	"fort/internal/store"

	"github.com/golang-jwt/jwt/v5"
)

var ErrUnauthorized = errors.New("unauthorized")

type Claims struct {
	AgentID string `json:"agent_id"`
	Type    string `json:"type"`
	jwt.RegisteredClaims
}

type Manager struct {
	SigningKey []byte
	Store      *store.Store
	Now        func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (m *Manager) Issue(agent model.Agent, ttl time.Duration, audience string) (string, model.TokenRecord, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := m.now()
	exp := now.Add(ttl)
	jti, err := randomHex(16)
	if err != nil {
		return "", model.TokenRecord{}, err
	}
	claims := Claims{
		AgentID: agent.ID,
		Type:    string(agent.Type),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   agent.ID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(m.SigningKey)
	if err != nil {
		return "", model.TokenRecord{}, err
	}
	rec := model.TokenRecord{
		JTI:       jti,
		AgentID:   agent.ID,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	if err := m.Store.PutToken(rec); err != nil {
		return "", model.TokenRecord{}, err
	}
	return signed, rec, nil
}

func (m *Manager) Parse(token string) (Claims, error) {
	parser := jwt.NewParser(jwt.WithTimeFunc(m.now))
	parsed, err := parser.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return m.SigningKey, nil
	})
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return Claims{}, ErrUnauthorized
	}
	if claims.ID == "" || claims.AgentID == "" {
		return Claims{}, ErrUnauthorized
	}
	rec, err := m.Store.GetToken(claims.ID)
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	now := m.now()
	if !rec.RevokedAt.IsZero() || now.After(rec.ExpiresAt) {
		return Claims{}, ErrUnauthorized
	}
	return *claims, nil
}

func (m *Manager) Revoke(jti, reason string) (model.TokenRecord, error) {
	return m.Store.RevokeToken(jti, reason, m.now())
}

func (m *Manager) List(agentID string, activeOnly bool) []model.TokenRecord {
	return m.Store.ListTokens(agentID, activeOnly, m.now())
}
