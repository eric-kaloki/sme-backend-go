package user

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/pkg/argon2"
	"github.com/machakos/sme-backend-go/pkg/resend"
)

var (
	ErrForbidden  = errors.New("forbidden")
	ErrConflict   = errors.New("conflict")
	ErrBadRequest = errors.New("bad request")
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

func (s *Service) CreateUser(req CreateUserRequest, creator *User) (*User, error) {
	if creator.Role != "SUPER_ADMIN" && creator.Role != "CHIEF_OFFICER" {
		return nil, ErrForbidden
	}

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

func (s *Service) GetAllUsers(search, role, status, sortBy, sortDir string, page, size int, requester *User) ([]User, int, error) {
	if roleHierarchy[requester.Role] < roleHierarchy["DIRECTOR"] {
		return nil, 0, ErrForbidden
	}

	if status == "DELETED" && requester.Role != "SUPER_ADMIN" {
		status = "ACTIVE"
	}

	return s.repo.SearchUsers(search, role, status, sortBy, sortDir, page, size)
}

func (s *Service) GetUserById(id string, requester *User) (*User, error) {
	if id != requester.ID && roleHierarchy[requester.Role] < roleHierarchy["DIRECTOR"] {
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

func (s *Service) UpdateUser(id string, req UpdateUserRequest, updater *User) (*User, error) {
	u, err := s.repo.FindByID(id)
	if err != nil || u.Status == "DELETED" {
		return nil, ErrUserNotFound
	}

	isSelfUpdate := u.ID == updater.ID
	if !isSelfUpdate && updater.Role != "SUPER_ADMIN" && updater.Role != "CHIEF_OFFICER" {
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
		u.Status = status
	}

	if err := s.repo.Update(u); err != nil {
		return nil, err
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

func (s *Service) DeleteUser(id string, deleter *User) error {
	if deleter.Role != "SUPER_ADMIN" {
		return ErrForbidden
	}
	if id == deleter.ID {
		return ErrBadRequest
	}

	u, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	if u.Role == "SUPER_ADMIN" {
		return ErrBadRequest // Disable instead of delete
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

func (s *Service) ResetPassword(id string, resetter *User) error {
	if resetter.Role != "SUPER_ADMIN" && resetter.Role != "CHIEF_OFFICER" {
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
