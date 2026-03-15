package domain

import (
	"encoding/json"
	"time"
)

// Job represents a unit of work in the certificate control plane.
type Job struct {
	ID           string    `json:"id"`
	Type         JobType   `json:"type"`
	CertificateID string   `json:"certificate_id"`
	TargetID     *string   `json:"target_id,omitempty"`
	Status       JobStatus `json:"status"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	LastError    *string   `json:"last_error,omitempty"`
	ScheduledAt  time.Time `json:"scheduled_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// JobType represents the classification of work to be performed.
type JobType string

const (
	JobTypeIssuance   JobType = "Issuance"
	JobTypeRenewal    JobType = "Renewal"
	JobTypeDeployment JobType = "Deployment"
	JobTypeValidation JobType = "Validation"
)

// JobStatus represents the execution state of a job.
type JobStatus string

const (
	JobStatusPending   JobStatus = "Pending"
	JobStatusRunning   JobStatus = "Running"
	JobStatusCompleted JobStatus = "Completed"
	JobStatusFailed    JobStatus = "Failed"
	JobStatusCancelled JobStatus = "Cancelled"
)

// DeploymentJob represents a job that deploys a certificate to a target via an agent.
type DeploymentJob struct {
	Job                `json:"job"`
	AgentID            string          `json:"agent_id"`
	DeploymentResult   json.RawMessage `json:"deployment_result,omitempty"`
}

// WorkItem enriches a Job with target details so the agent knows which connector to use.
// Returned by GET /api/v1/agents/{id}/work.
type WorkItem struct {
	ID            string          `json:"id"`
	Type          JobType         `json:"type"`
	CertificateID string          `json:"certificate_id"`
	TargetID      *string         `json:"target_id,omitempty"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetConfig  json.RawMessage `json:"target_config,omitempty"`
	Status        JobStatus       `json:"status"`
}
