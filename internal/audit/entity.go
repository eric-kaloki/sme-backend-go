package audit

import (
	"encoding/json"
	"time"
)

type AuditLog struct {
	ID          string     `db:"id" json:"id"`
	Action      string     `db:"action" json:"action"`
	EntityType  string     `db:"entity_type" json:"entityType"`
	EntityID    *string    `db:"entity_id" json:"entityId,omitempty"`
	OldData     *string    `db:"old_data" json:"oldData,omitempty"`
	NewData     *string    `db:"new_data" json:"newData,omitempty"`
	Description *string    `db:"description" json:"description,omitempty"`
	IPAddress   *string    `db:"ip_address" json:"ipAddress,omitempty"`
	UserAgent   *string    `db:"user_agent" json:"userAgent,omitempty"`
	UserID      *string    `db:"user_id" json:"userId,omitempty"`
	SMEID       *string    `db:"sme_id" json:"smeId,omitempty"`
	CreatedAt   time.Time  `db:"created_at" json:"createdAt"`
	UpdatedAt   *time.Time `db:"updated_at" json:"updatedAt,omitempty"`
}

// Helper to reliably marshal interface maps to JSON strings for DB insertion
func MarshalData(data map[string]interface{}) *string {
	if data == nil || len(data) == 0 {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	str := string(b)
	return &str
}
