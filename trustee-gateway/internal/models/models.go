package models

import (
	"time"

	"gorm.io/gorm"
)

// InstanceInfo represents the information about an attestation agent instance
type InstanceInfo struct {
	InstanceID     string `json:"instance_id" gorm:"column:instance_id"`           // AA instance ID
	ImageID        string `json:"image_id" gorm:"column:image_id"`                 // AA image ID
	InstanceName   string `json:"instance_name" gorm:"column:instance_name"`       // AA instance name
	OwnerAccountID string `json:"owner_account_id" gorm:"column:owner_account_id"` // AA owner account ID
}

// AttestationRecord represents a record of an attestation request
type AttestationRecord struct {
	gorm.Model
	ClientIP      string            `json:"client_ip"`
	SessionID     string            `json:"session_id"`
	RequestBody   string            `json:"request_body"`
	Claims        string            `json:"claims"`
	Status        int               `json:"status"`
	Successful    bool              `json:"successful"`
	Timestamp     time.Time         `json:"timestamp"`
	SourceService string            `json:"source_service"` // Indicates the source of the attestation (e.g., "kbs", "attestation-service")
	InstanceInfo  `gorm:"embedded"` // Embedded AA instance information
}

// ResourceRequest represents a record of a resource request
type ResourceRequest struct {
	gorm.Model
	ClientIP     string            `json:"client_ip"`
	SessionID    string            `json:"session_id"`
	Repository   string            `json:"repository"`
	Type         string            `json:"type"`
	Tag          string            `json:"tag"`
	Method       string            `json:"method"` // "GET" or "POST"
	Status       int               `json:"status"`
	Successful   bool              `json:"successful"`
	Timestamp    time.Time         `json:"timestamp"`
	InstanceInfo `gorm:"embedded"` // Embedded AA instance information
}

// AAInstanceHeartbeat represents a heartbeat record from an attestation agent instance
type AAInstanceHeartbeat struct {
	gorm.Model
	InstanceInfo  `gorm:"embedded"` // Embedded AA instance information
	ClientIP      string            `json:"client_ip"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
}

// AttestationRecordsResponse represents the response for listing attestation records
type AttestationRecordsResponse struct {
	Data  []AttestationRecord `json:"data"`
	Total int64               `json:"total"`
}

// ResourceRequestsResponse represents the response for listing resource requests
type ResourceRequestsResponse struct {
	Data  []ResourceRequest `json:"data"`
	Total int64             `json:"total"`
}
