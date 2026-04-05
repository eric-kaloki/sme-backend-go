package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/internal/user"
)

var (
	ErrForbidden   = errors.New("Forbidden: Insufficient permissions")
	ErrBadRequest  = errors.New("Bad Request: Invalid action, empty permissions, or self-interference")
	ErrUserNotFound = errors.New("User not found")
)

type Service struct {
	repo      *Repository
	userRepo  *user.Repository
	auditRepo *audit.Repository
}

func NewService(repo *Repository, userRepo *user.Repository, auditRepo *audit.Repository) *Service {
	return &Service{
		repo:      repo,
		userRepo:  userRepo,
		auditRepo: auditRepo,
	}
}

// GetAllPermissions returns all active system permissions
func (s *Service) GetAllPermissions() ([]Permission, error) {
	return s.repo.FindAllPermissions()
}

// GetUserPermissions calculated the effective permission set for a user with rich metadata for the frontend
func (s *Service) GetUserPermissions(userId string, requester *common.AuthenticatedUser) (*UserPermissionsResponse, error) {
	// Security check: Only self or authorized delegates/admins can see detailed permissions.
	// We allow nil requester for internal system calls (e.g., during login).
	if requester != nil {
		if userId != requester.ID && requester.Role != "SUPER_ADMIN" && !requester.HasPermission("permission:delegate") && !requester.HasPermission("user:read") {
			return nil, ErrForbidden
		}
	}

	u, err := s.userRepo.FindByID(userId)
	if err != nil {
		return nil, err
	}

	// 1. Fetch all system permissions for lookup
	allPerms, err := s.repo.FindAllPermissions()
	if err != nil {
		return nil, err
	}
	permLookup := make(map[string]Permission)
	for _, p := range allPerms {
		permLookup[p.Name] = p
	}

	// 2. Parse custom permissions JSON
	var customPermNames []string
	if u.CustomPermissions != nil && *u.CustomPermissions != "" {
		if err := json.Unmarshal([]byte(*u.CustomPermissions), &customPermNames); err != nil {
			log.Printf("Warning: failed to parse custom permissions for user %s: %v", userId, err)
		}
	}

	// 3. Get base permissions from role
	rolePermNames, err := s.repo.FindRolePermissionsByName(u.Role)
	if err != nil {
		return nil, err
	}

	// 4. Build detailed permissions list
	roleMap := make(map[string]bool)
	allUniqueNames := make(map[string]bool)

	if u.Role == "SUPER_ADMIN" {
		// Super Admin automatically gets ALL active permissions
		for name := range permLookup {
			allUniqueNames[name] = true
			roleMap[name] = true
		}
	} else {
		for _, name := range rolePermNames {
			roleMap[name] = true
			allUniqueNames[name] = true
		}
		for _, name := range customPermNames {
			allUniqueNames[name] = true
		}
	}

	details := make([]PermissionDetail, 0)
	for name := range allUniqueNames {
		p, exists := permLookup[name]
		if !exists {
			continue
		}

		source := "role"
		if !roleMap[name] {
			source = "delegated"
		}

		details = append(details, PermissionDetail{
			Name:        p.Name,
			Source:      source,
			DisplayName: p.DisplayName,
			Description: stringPtrToString(p.Description),
			Category:    p.Category,
			Resource:    stringPtrToString(p.Resource),
			Action:      stringPtrToString(p.Action),
		})
	}

	// Sort for stability
	sort.Slice(details, func(i, j int) bool {
		return details[i].Name < details[j].Name
	})

	resp := &UserPermissionsResponse{
		Permissions: details,
		Summary: UserPermissionsSummary{
			RolePermissions:      len(rolePermNames),
			DelegatedPermissions: len(allUniqueNames) - len(rolePermNames),
			TotalPermissions:     len(allUniqueNames),
		},
	}
	resp.User.ID = u.ID
	resp.User.Name = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	resp.User.Email = u.Email
	resp.User.Role = u.Role

	return resp, nil
}

func stringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// UpdateUserPermissions implements the logic from the Java counterpart to add/remove custom JSON permissions
func (s *Service) UpdateUserPermissions(userId, action string, permissions []string, updater *common.AuthenticatedUser) (*user.User, error) {
	// 1. Security Check
	// - Block self-interference (prevent users from managing their own extra permissions)
	if userId == updater.ID {
		return nil, fmt.Errorf("%w: You cannot manage your own permissions", ErrForbidden)
	}

	// - Permission check (SUPER_ADMIN or explicit delegate permission)
	if updater.Role != "SUPER_ADMIN" && !updater.HasPermission("permission:delegate") {
		return nil, ErrForbidden
	}

	// - Recursive check: Ensure delegator actually has the permissions they are trying to delegate
	if updater.Role != "SUPER_ADMIN" {
		for _, p := range permissions {
			if !updater.HasPermission(p) {
				return nil, fmt.Errorf("%w: You cannot delegate permission '%s' because you don't possess it", ErrForbidden, p)
			}
		}
	}

	// 2. Validation
	action = strings.ToLower(action)
	if action != "add" && action != "remove" {
		return nil, fmt.Errorf("%w: Unknown action", ErrBadRequest)
	}
	if len(permissions) == 0 {
		return nil, fmt.Errorf("%w: Permissions list cannot be empty", ErrBadRequest)
	}

	// 3. Strict Permission Whitelisting
	allPerms, err := s.repo.FindAllPermissions()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permission dictionary: %w", err)
	}
	validPerms := make(map[string]bool)
	for _, p := range allPerms {
		validPerms[p.Name] = true
	}
	for _, p := range permissions {
		if !validPerms[p] {
			return nil, fmt.Errorf("%w: unknown permission '%s'", ErrBadRequest, p)
		}
	}

	// 4. Fetch target user
	targetUser, err := s.userRepo.FindByID(userId)
	if err != nil {
		return nil, err
	}

	// 5. Parse current custom permissions
	var current []string
	if targetUser.CustomPermissions != nil && *targetUser.CustomPermissions != "" {
		_ = json.Unmarshal([]byte(*targetUser.CustomPermissions), &current)
	}

	// Capture old data for audit
	oldData := map[string]interface{}{
		"customPermissions": current,
	}

	// 6. Update logic
	updated := make([]string, 0)
	if action == "add" {
		permMap := make(map[string]bool)
		for _, p := range current {
			permMap[p] = true
		}
		for _, p := range permissions {
			permMap[p] = true
		}
		for p := range permMap {
			updated = append(updated, p)
		}
	} else {
		toRemove := make(map[string]bool)
		for _, p := range permissions {
			toRemove[p] = true
		}
		for _, p := range current {
			if !toRemove[p] {
				updated = append(updated, p)
			}
		}
	}
	sort.Strings(updated)

	// 7. Save back as JSON
	var jsonStr *string
	if len(updated) > 0 {
		bytes, _ := json.Marshal(updated)
		s := string(bytes)
		jsonStr = &s
	}
	targetUser.CustomPermissions = jsonStr

	// Use Atomic Update to prevent race conditions
	if err := s.userRepo.UpdateCustomPermissions(userId, jsonStr); err != nil {
		return nil, err
	}

	// 7. Audit Log
	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "USER_UPDATE",
		EntityType:  "USER",
		EntityID:    &targetUser.ID,
		UserID:      &updater.ID,
		Description: ptr(fmt.Sprintf("%s custom permissions for user: %s", strings.Title(action), targetUser.Email)),
		OldData:     audit.MarshalData(oldData),
		NewData:     audit.MarshalData(map[string]interface{}{"customPermissions": updated}),
	})

	return targetUser, nil
}

func ptr(s string) *string { return &s }
