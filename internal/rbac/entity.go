package rbac

import (
	"time"
)

// Permission represents a specific action/resource capability
type Permission struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"displayName"`
	Description *string   `db:"description" json:"description"`
	Category    string    `db:"category" json:"category"`
	Resource    *string   `db:"resource" json:"resource"`
	Action      *string   `db:"action" json:"action"`
	IsActive    bool      `db:"is_active" json:"isActive"`
	CreatedAt   time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt   time.Time `db:"updated_at" json:"updatedAt"`
}

// Role represents a collection of permissions
type Role struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	DisplayName string    `db:"display_name" json:"displayName"`
	Description *string   `db:"description" json:"description"`
	Color       *string   `db:"color" json:"color"`
	Priority    int       `db:"priority" json:"priority"`
	IsSystem    bool      `db:"is_system" json:"isSystem"`
	IsActive    bool      `db:"is_active" json:"isActive"`
	CreatedAt   time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt   time.Time `db:"updated_at" json:"updatedAt"`
}

// RolePermission links roles to permissions
type RolePermission struct {
	ID           string     `db:"id" json:"id"`
	RoleID       string     `db:"role_id" json:"roleId"`
	PermissionID string     `db:"permission_id" json:"permissionId"`
	Granted      time.Time  `db:"granted" json:"granted"`
	Revoked      *time.Time `db:"revoked" json:"revoked"`
	CreatedAt    time.Time  `db:"created_at" json:"createdAt"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updatedAt"`
}

// PermissionDetail represents a permission with source metadata for the frontend
type PermissionDetail struct {
	Name        string `json:"name"`
	Source      string `json:"source"` // "role" or "delegated"
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// UserPermissionsSummary provides quick stats for the UI
type UserPermissionsSummary struct {
	RolePermissions      int `json:"rolePermissions"`
	DelegatedPermissions int `json:"delegatedPermissions"`
	TotalPermissions     int `json:"totalPermissions"`
}

// UserPermissionsResponse returns the rich effective permissions for a user
type UserPermissionsResponse struct {
	User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	} `json:"user"`
	Permissions []PermissionDetail     `json:"permissions"`
	Summary     UserPermissionsSummary `json:"summary"`
}

// EffectivePermissionNames returns just the names of all unique active permissions
func (r *UserPermissionsResponse) EffectivePermissionNames() []string {
	names := make([]string, len(r.Permissions))
	for i, p := range r.Permissions {
		names[i] = p.Name
	}
	return names
}

// PermissionsListResponse wraps the list of system permissions
type PermissionsListResponse struct {
	Permissions []Permission `json:"permissions"`
}

// UpdateUserPermissionsRequest matches the request body for updating permissions
type UpdateUserPermissionsRequest struct {
	Action      string   `json:"action"`      // "add" or "remove"
	Permissions []string `json:"permissions"` // List of permission names
}
