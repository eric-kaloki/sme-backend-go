package user

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/pkg/argon2"
	"github.com/machakos/sme-backend-go/pkg/resend"
)

var (
	ErrForbidden  = errors.New("Forbidden")
	ErrConflict   = errors.New("Conflict")
	ErrBadRequest = errors.New("Bad Request")
)

var validRoles = map[string]bool{
	"SME_OFFICER":   true,
	"DIRECTOR":      true,
	"CHIEF_OFFICER": true,
	"SUPER_ADMIN":   true,
}

var validStatuses = map[string]bool{
	"ACTIVE":   true,
	"PENDING":  true,
	"DISABLED": true,
	"DELETED":  true,
}

var roleHierarchy = map[string]int{
	"SME_OFFICER":   1,
	"DIRECTOR":      2,
	"CHIEF_OFFICER": 3,
	"SUPER_ADMIN":   4,
}

type Service struct {
	repo      *Repository
	auditRepo *audit.Repository
	mailer    *resend.Mailer
}

func NewService(repo *Repository, auditRepo *audit.Repository, mailer *resend.Mailer) *Service {
	return &Service{
		repo:      repo,
		auditRepo: auditRepo,
		mailer:    mailer,
	}
}

func ptr(s string) *string { return &s }

func GenerateTempPassword(length int) string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	var current []byte
	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		current = append(current, chars[num.Int64()])
	}
	return string(current)
}

func (s *Service) CreateUser(req CreateUserRequest, creator *common.AuthenticatedUser) (*User, error) {
	// 1. Security Check
	if creator.Role != "SUPER_ADMIN" && !creator.HasPermission("user:create") {
		return nil, ErrForbidden
	}

	// 2. XSS Sanitization
	req.FirstName = common.Sanitize(req.FirstName)
	req.LastName = common.Sanitize(req.LastName)
	req.Username = common.Sanitize(req.Username)

	req.Email = strings.ToLower(req.Email)
	req.Username = strings.ToLower(req.Username)
	if _, err := s.repo.FindByEmail(req.Email); err == nil {
		return nil, ErrConflict
	}
	if _, err := s.repo.FindByUsername(req.Username); err == nil {
		return nil, ErrConflict
	}

	role := strings.ToUpper(req.Role)
	if !validRoles[role] {
		return nil, ErrBadRequest
	}
	if role == "SUPER_ADMIN" && creator.Role != "SUPER_ADMIN" {
		return nil, ErrForbidden
	}

	tempPassword := GenerateTempPassword(12)
	hashed, err := argon2.HashPassword(tempPassword)
	if err != nil {
		return nil, err
	}

	newUser := &User{
		ID:                  uuid.NewString(),
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		Email:               req.Email,
		Username:            req.Username,
		Password:            hashed,
		Phone:               req.Phone,
		Role:                role,
		Status:              "ACTIVE",
		IsTemporaryPassword: true,
	}

	if err := s.repo.Create(newUser); err != nil {
		return nil, err
	}

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "USER_CREATE",
		EntityType:  "USER",
		EntityID:    &newUser.ID,
		UserID:      &creator.ID,
		Description: ptr("Created user: " + newUser.Email),
		NewData:     audit.MarshalData(map[string]interface{}{"id": newUser.ID, "email": newUser.Email, "role": newUser.Role}),
	})

	s.mailer.SendUserCredentials(newUser.Email, newUser.FirstName, newUser.LastName, newUser.Username, tempPassword, newUser.Role)

	return newUser, nil
}

func (s *Service) GetAllUsers(search, role, status, sortBy, sortDir string, page, size int, requester *common.AuthenticatedUser) ([]User, int, error) {
	if requester.Role != "SUPER_ADMIN" && !requester.HasPermission("user:read") {
		return nil, 0, ErrForbidden
	}

	if status == "DELETED" && requester.Role != "SUPER_ADMIN" {
		status = "ACTIVE"
	}

	return s.repo.SearchUsers(search, role, status, sortBy, sortDir, page, size)
}

func (s *Service) GetUserById(id string, requester *common.AuthenticatedUser) (*User, error) {
	if id != requester.ID && requester.Role != "SUPER_ADMIN" && !requester.HasPermission("user:read") {
		return nil, ErrForbidden
	}

	u, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}

	if u.Status == "DELETED" && id != requester.ID {
		return nil, ErrUserNotFound
	}

	return u, nil
}

func (s *Service) UpdateUser(id string, req UpdateUserRequest, updater *common.AuthenticatedUser) (*User, error) {
	// 1. XSS Sanitization
	req.FirstName = common.SanitizePtr(req.FirstName)
	req.LastName = common.SanitizePtr(req.LastName)

	u, err := s.repo.FindByID(id)
	if err != nil || u.Status == "DELETED" {
		return nil, ErrUserNotFound
	}

	isSelfUpdate := u.ID == updater.ID
	if isSelfUpdate {
		// Users can update their basic profile, but NOT sensitive administrative fields
		if req.Role != nil || req.Status != nil {
			return nil, fmt.Errorf("%w: you cannot change your own role or status", ErrForbidden)
		}
	} else if updater.Role != "SUPER_ADMIN" && !updater.HasPermission("user:update") {
		return nil, ErrForbidden
	}

	oldDataMap := map[string]interface{}{"email": u.Email, "firstName": u.FirstName, "lastName": u.LastName, "phone": u.Phone, "status": u.Status, "role": u.Role}
	oldData := audit.MarshalData(oldDataMap)

	if req.FirstName != nil {
		u.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		u.LastName = *req.LastName
	}
	if req.Phone != nil {
		u.Phone = req.Phone
	}
	if req.Email != nil && !strings.EqualFold(*req.Email, u.Email) {
		lowered := strings.ToLower(*req.Email)
		if existing, err := s.repo.FindByEmail(lowered); err == nil && existing.ID != u.ID {
			return nil, ErrConflict
		}
		u.Email = lowered
	}

	hasRoleChange := false
	hasStatusChange := false
	if !isSelfUpdate && req.Role != nil {
		newRole := strings.ToUpper(*req.Role)
		if newRole != u.Role {
			if !validRoles[newRole] {
				return nil, ErrBadRequest
			}
			currLvl := roleHierarchy[u.Role]
			newLvl := roleHierarchy[newRole]
			isPromotion := newLvl > currLvl

			if isPromotion {
				if updater.Role != "SUPER_ADMIN" && updater.Role != "CHIEF_OFFICER" {
					return nil, ErrForbidden
				}
				if newRole == "SUPER_ADMIN" && updater.Role != "SUPER_ADMIN" {
					return nil, ErrForbidden
				}
				if updater.Role != "SUPER_ADMIN" && newLvl >= roleHierarchy[updater.Role] {
					return nil, ErrForbidden
				}
			} else {
				// Only SUPER_ADMIN can demote
				if updater.Role != "SUPER_ADMIN" {
					return nil, ErrForbidden
				}
			}
			u.Role = newRole
			hasRoleChange = true
		}
	}

	if !isSelfUpdate && req.Status != nil {
		status := strings.ToUpper(*req.Status)
		if !validStatuses[status] {
			return nil, ErrBadRequest
		}
		if (status == "DISABLED" || status == "DELETED") && updater.Role != "SUPER_ADMIN" {
			return nil, ErrForbidden
		}
		if status != u.Status {
			u.Status = status
			hasStatusChange = true
		}
	}

	// 7. Save Changes
	// If only administrative fields changed, use Atomic Update to prevent race conditions
	// If profile fields also changed, use full Update (still susceptible but protects metadata better)
	if hasRoleChange || hasStatusChange {
		// Profile fields also changed?
		profileChanged := req.FirstName != nil || req.LastName != nil || req.Phone != nil || (req.Email != nil && strings.ToLower(*req.Email) != u.Email)
		
		if !profileChanged {
			// Only Role/Status changed: Use Atomic Update
			if err := s.repo.UpdateRoleAndStatus(u.ID, u.Role, u.Status); err != nil {
				return nil, err
			}
		} else {
			// Mixed updates: Full row update required
			if err := s.repo.Update(u); err != nil {
				return nil, err
			}
		}
	} else {
		// Only profile fields changed (or nothing): Standard update
		if err := s.repo.Update(u); err != nil {
			return nil, err
		}
	}

	action := "USER_UPDATE"
	if hasRoleChange {
		action = "USER_PROMOTE" // Prioritizing role change for audit
	}

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      action,
		EntityType:  "USER",
		EntityID:    &u.ID,
		UserID:      &updater.ID,
		Description: ptr("Updated user: " + u.Email),
		OldData:     oldData,
		NewData:     audit.MarshalData(map[string]interface{}{"email": u.Email, "firstName": u.FirstName, "lastName": u.LastName, "phone": u.Phone, "status": u.Status, "role": u.Role}),
	})

	return u, nil
}

func (s *Service) DeleteUser(id string, deleter *common.AuthenticatedUser) error {
	if deleter.Role != "SUPER_ADMIN" && !deleter.HasPermission("user:delete") {
		return ErrForbidden
	}
	if id == deleter.ID {
		return ErrBadRequest
	}

	u, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	// Super Admin Protection: Only a Super Admin can delete another Super Admin
	if u.Role == "SUPER_ADMIN" && deleter.Role != "SUPER_ADMIN" {
		return fmt.Errorf("%w: only a super admin can delete another super admin", ErrForbidden)
	}
	if u.Status == "DELETED" {
		return ErrBadRequest
	}

	u.Status = "DELETED"
	u.Email = u.Email + "_deleted_" + uuid.NewString()
	u.Username = u.Username + "_deleted_" + uuid.NewString()

	if err := s.repo.Update(u); err != nil {
		return err
	}

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "USER_DELETE",
		EntityType:  "USER",
		EntityID:    &u.ID,
		UserID:      &deleter.ID,
		Description: ptr("Deleted user"),
	})

	return nil
}

func (s *Service) ResetPassword(id string, resetter *common.AuthenticatedUser) error {
	if resetter.Role != "SUPER_ADMIN" && !resetter.HasPermission("user:update") {
		return ErrForbidden
	}

	u, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}

	tempPassword := GenerateTempPassword(12)
	hashed, err := argon2.HashPassword(tempPassword)
	if err != nil {
		return err
	}

	u.Password = hashed
	u.IsTemporaryPassword = true

	if err := s.repo.Update(u); err != nil {
		return err
	}

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "PASSWORD_RESET",
		EntityType:  "USER",
		EntityID:    &u.ID,
		UserID:      &resetter.ID,
		Description: ptr("Password reset for user: " + u.Email),
	})

	// Assuming we want to email the password
	// In Java the generic email service has sendPasswordReset, we'll reuse SendUserCredentials for simplicity here
	// or we can just add SendPasswordReset to mailer.
	s.mailer.SendUserCredentials(u.Email, u.FirstName, u.LastName, u.Username, tempPassword, u.Role)
	return nil
}

func (s *Service) GetUserAuditLogs(userId string, page, size int) (map[string]interface{}, error) {
	u, err := s.repo.FindByID(userId)
	if err != nil {
		return nil, err
	}

	logs, total, err := s.auditRepo.SearchAuditLogs("", "", userId, "", "", "createdAt", "DESC", page, size)
	if err != nil {
		return nil, err
	}

	for i := range logs {
		audit.MapToResponse(&logs[i])
	}

	totalPages := total / size
	if total%size > 0 {
		totalPages++
	}

	return map[string]interface{}{
		"user": map[string]interface{}{
			"id":        u.ID,
			"firstName": u.FirstName,
			"lastName":  u.LastName,
			"email":     u.Email,
			"role":      u.Role,
		},
		"auditLogs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      size,
			"total":      total,
			"totalPages": totalPages,
			"hasNext":    page < totalPages-1,
			"hasPrev":    page > 0,
		},
	}, nil
}
