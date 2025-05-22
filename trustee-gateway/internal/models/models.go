package models

import (
	"time"

	"gorm.io/gorm"
)

// Resource represents a resource in the KBS system
type Resource struct {
	gorm.Model
	Repository string `json:"repository"`
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Metadata   string `json:"metadata"`
}

// AttestationPolicy represents an attestation policy in the KBS
type AttestationPolicy struct {
	gorm.Model
	PolicyID string `json:"policy_id"`
	Type     string `json:"type"`
	Policy   []byte `json:"policy"`
	Metadata string `json:"metadata"`
}

// ResourcePolicy represents a resource policy in the KBS
type ResourcePolicy struct {
	gorm.Model
	Policy   []byte `json:"policy"`
	Metadata string `json:"metadata"`
}

// AttestationRecord represents a record of an attestation request
type AttestationRecord struct {
	gorm.Model
	ClientIP    string    `json:"client_ip"`
	SessionID   string    `json:"session_id"`
	RequestBody string    `json:"request_body"`
	Claims      string    `json:"claims"`
	Status      int       `json:"status"`
	Successful  bool      `json:"successful"`
	Timestamp   time.Time `json:"timestamp"`
}

// ResourceRequest represents a record of a resource request
type ResourceRequest struct {
	gorm.Model
	ClientIP   string    `json:"client_ip"`
	SessionID  string    `json:"session_id"`
	Repository string    `json:"repository"`
	Type       string    `json:"type"`
	Tag        string    `json:"tag"`
	Method     string    `json:"method"` // "GET" or "POST"
	Status     int       `json:"status"`
	Successful bool      `json:"successful"`
	Timestamp  time.Time `json:"timestamp"`
}
