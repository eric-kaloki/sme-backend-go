package audit

import (
	"encoding/json"
	"time"
)

type UserMin struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

type LogExportRequest struct {
	EntityType  string                 `json:"entityType"`
	Action      string                 `json:"action"`
	RecordCount int                    `json:"recordCount"`
	Filename    string                 `json:"filename"`
	Filters     map[string]interface{} `json:"filters"`
	Description string                 `json:"description"`
}

type AuditLogResponse struct {
	ID          string                 `json:"id" db:"id"`
	Action      string                 `json:"action" db:"action"`
	EntityType  string                 `json:"entityType" db:"entity_type"`
	EntityID    *string                `json:"entityId" db:"entity_id"`
	RawOldData  *string                `json:"-" db:"old_data"`
	RawNewData  *string                `json:"-" db:"new_data"`
	OldData     map[string]interface{} `json:"oldData"`
	NewData     map[string]interface{} `json:"newData"`
	Description *string                `json:"description" db:"description"`
	IPAddress   *string                `json:"ipAddress" db:"ip_address"`
	UserAgent   *string                `json:"userAgent" db:"user_agent"`
	SMEID       *string                `json:"smeId" db:"sme_id"`
	CreatedAt   time.Time              `json:"createdAt" db:"created_at"`
	UpdatedAt   *time.Time             `json:"updatedAt" db:"updated_at"`

	// Flattened from join
	UserID      *string                `json:"userId" db:"user_id"`
	FirstName   *string                `json:"-" db:"user_first_name"`
	LastName    *string                `json:"-" db:"user_last_name"`
	Email       *string                `json:"-" db:"user_email"`

	User        *UserMin               `json:"user,omitempty"`
}

func mapToResponse(log *AuditLogResponse) *AuditLogResponse {
	if log.RawOldData != nil {
		var o map[string]interface{}
		if err := json.Unmarshal([]byte(*log.RawOldData), &o); err == nil {
			log.OldData = o
		}
	}
	if log.RawNewData != nil {
		var n map[string]interface{}
		if err := json.Unmarshal([]byte(*log.RawNewData), &n); err == nil {
			log.NewData = n
		}
	}

	if log.UserID != nil {
		first := ""
		last := ""
		email := ""
		if log.FirstName != nil { first = *log.FirstName }
		if log.LastName != nil { last = *log.LastName }
		if log.Email != nil { email = *log.Email }

		log.User = &UserMin{
			ID:        *log.UserID,
			FirstName: first,
			LastName:  last,
			Email:     email,
		}
	}
	return log
}
