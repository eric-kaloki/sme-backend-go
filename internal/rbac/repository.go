package rbac

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

var (
	ErrPermissionNotFound = errors.New("permission not found")
	ErrRoleNotFound       = errors.New("role not found")
)

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

// FindAllPermissions retrieves all active permissions
func (r *Repository) FindAllPermissions() ([]Permission, error) {
	var permissions []Permission
	err := r.db.Select(&permissions, "SELECT * FROM permissions WHERE is_active = true ORDER BY category, name")
	return permissions, err
}

// FindRolePermissionsByName retrieves all permission names for a given role name
func (r *Repository) FindRolePermissionsByName(roleName string) ([]string, error) {
	query := `
		SELECT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		WHERE r.name = $1 AND r.is_active = true AND p.is_active = true AND rp.revoked IS NULL
	`
	var permissionNames []string
	err := r.db.Select(&permissionNames, query, roleName)
	if err != nil {
		return nil, err
	}
	return permissionNames, nil
}

// FindAllRoleNames retrieves all available role names
func (r *Repository) FindAllRoleNames() ([]string, error) {
	var names []string
	err := r.db.Select(&names, "SELECT name FROM roles WHERE is_active = true ORDER BY priority DESC")
	return names, err
}

// FindRoleByID retrieves a role by its ID
func (r *Repository) FindRoleByID(id string) (*Role, error) {
	var role Role
	err := r.db.Get(&role, "SELECT * FROM roles WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// FindPermissionByName retrieves a permission by its unique name
func (r *Repository) FindPermissionByName(name string) (*Permission, error) {
	var perm Permission
	err := r.db.Get(&perm, "SELECT * FROM permissions WHERE name = $1", name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrPermissionNotFound
		}
		return nil, err
	}
	return &perm, nil
}

func (r *Repository) GetEffectivePermissions(userId string, baseRole string, customPerms []string) ([]string, error) {
	// 1. Get Base permissions from Role
	rolePerms, err := r.FindRolePermissionsByName(baseRole)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch role permissions: %w", err)
	}

	// 2. Merge with custom permissions
	permMap := make(map[string]bool)
	for _, p := range rolePerms {
		permMap[p] = true
	}
	for _, p := range customPerms {
		permMap[p] = true
	}

	effective := make([]string, 0, len(permMap))
	for p := range permMap {
		effective = append(effective, p)
	}

	return effective, nil
}
