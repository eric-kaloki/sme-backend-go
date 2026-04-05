package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/internal/rbac"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/argon2"
	"github.com/machakos/sme-backend-go/pkg/jwt"
	"github.com/machakos/sme-backend-go/pkg/resend"
)

type Handler struct {
	userRepo    *user.Repository
	auditRepo   *audit.Repository
	jwt         *jwt.TokenProvider
	revoker     jwt.Revoker // Fix #3: needed for logout revocation
	mailer      *resend.Mailer
	rbac        *rbac.Service
	validate    *validator.Validate
	frontendURL string // Fix #14: no more hardcoded URLs
}

func NewHandler(
	userRepo *user.Repository,
	auditRepo *audit.Repository,
	jwtProv *jwt.TokenProvider,
	revoker jwt.Revoker,
	mailer *resend.Mailer,
	frontendURL string,
	rbacService *rbac.Service,
) *Handler {
	return &Handler{
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		jwt:         jwtProv,
		revoker:     revoker,
		mailer:      mailer,
		rbac:        rbacService,
		validate:    validator.New(),
		frontendURL: frontendURL,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ─────────────────────────────────────────────────────────────────────────────

type LoginRequest struct {
	Email    string `json:"email"    validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	ID                string     `json:"id"`
	FirstName         string     `json:"firstName"`
	LastName          string     `json:"lastName"`
	Email             string     `json:"email"`
	Username          string     `json:"username"`
	Phone             *string    `json:"phone"`
	Role              string     `json:"role"`
	Status            string     `json:"status"`
	Permissions       []string   `json:"permissions"`
	CustomPermissions *string    `json:"customPermissions"`
	LastLogin         *time.Time `json:"lastLogin"`
}

// LoginResponse — Fix #4: Token and RefreshToken are now genuinely different tokens.
type LoginResponse struct {
	Token                  string       `json:"token"`
	RefreshToken           string       `json:"refreshToken"`
	Admin                  UserResponse `json:"admin"`
	SessionTimeout         int          `json:"sessionTimeout"`
	RequiresPasswordChange bool         `json:"requiresPasswordChange"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Login
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	u, err := h.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Fallback: allow login with username in the email field
		u, err = h.userRepo.FindByUsername(req.Email)
		if err != nil {
			h.logFailedLogin(r, req.Email)
			common.RespondError(w, http.StatusUnauthorized, "Invalid email, username, or password", nil)
			return
		}
	}

	// 1. Check for Account Lock
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		h.logFailedLoginUser(r, u)
		common.RespondError(w, http.StatusForbidden, "Account is temporarily locked due to multiple failed login attempts. Please try again later.", nil)
		return
	}

	match, err := argon2.CheckPassword(req.Password, u.Password)
	if err != nil || !match {
		h.logFailedLoginUser(r, u)
		// Atomic Increment failure count and potentially lock
		_ = h.userRepo.IncrementFailedLogin(u.ID)
		common.RespondError(w, http.StatusUnauthorized, "Invalid email, username, or password", nil)
		return
	}

	// 2. Successful Login: Reset Failure Count
	if u.FailedLoginCount > 0 || u.LockedUntil != nil {
		_ = h.userRepo.ResetFailedLogin(u.ID)
	}

	if u.Status != "ACTIVE" {
		common.RespondError(w, http.StatusForbidden, "User account is not active", errors.New("user_status_"+u.Status))
		return
	}

	// RBAC Integration: Calculate effective permissions instead of raw unmarshal
	// Pass nil as requester for internal system lookup during login
	permSet, err := h.rbac.GetUserPermissions(u.ID, nil)
	var permNames []string
	if err != nil {
		log.Printf("ERROR: Failed to resolve permissions for %s: %v", u.Email, err)
		// Fallback to empty if DB has issues but don't block login
		permNames = []string{}
	} else {
		permNames = permSet.EffectivePermissionNames()
	}

	// Fix #4: Generate a real token pair — access and refresh have different secrets and TTLs.
	tokenPair, err := h.jwt.GenerateTokenPair(u.ID, u.Username, u.Email, u.Role, permNames)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to generate token", err)
		return
	}

	h.auditRepo.LogAsync(audit.AuditLog{
		Action:      "LOGIN",
		EntityType:  "AUTH",
		UserID:      &u.ID,
		Description: h.ptr("User logged in: " + u.Email),
		IPAddress:   h.ptr(r.RemoteAddr),
		UserAgent:   h.ptr(r.Header.Get("User-Agent")),
	})

	go h.userRepo.UpdateLastLogin(u.ID)

	response := LoginResponse{
		Token:                  tokenPair.AccessToken,
		RefreshToken:           tokenPair.RefreshToken,
		SessionTimeout:         3600, // 1 hour in seconds, matching JWT_EXPIRATION_HOURS=1
		RequiresPasswordChange: u.IsTemporaryPassword,
		Admin: UserResponse{
			ID:                u.ID,
			FirstName:         u.FirstName,
			LastName:          u.LastName,
			Email:             u.Email,
			Username:          u.Username,
			Phone:             u.Phone,
			Role:              u.Role,
			Status:            u.Status,
			Permissions:       permNames,
			CustomPermissions: u.CustomPermissions,
			LastLogin:         u.LastLogin,
		},
	}

	common.RespondSuccess(w, http.StatusOK, "Login successful", response)
}

// ─────────────────────────────────────────────────────────────────────────────
// Logout — Fix #3: actually revoke the access token
// ─────────────────────────────────────────────────────────────────────────────

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())

	// Revoke the access token from the Authorization header.
	// extractBearerToken is safe to call — middleware already confirmed the
	// header exists, so this cannot fail in practice.
	if tokenString, err := extractBearerToken(r); err == nil {
		if claims, err := h.jwt.ValidateAccessToken(tokenString); err == nil {
			// Revoke until its natural expiry so we don't keep it forever
			h.revoker.Revoke(claims.ID, claims.ExpiresAt.Time)
		}
	}

	// Also revoke the refresh token if the client provides it.
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.RefreshToken != "" {
		if claims, err := h.jwt.ValidateRefreshToken(req.RefreshToken); err == nil {
			h.revoker.Revoke(claims.ID, claims.ExpiresAt.Time)
		}
	}

	if reqUser != nil {
		h.auditRepo.LogAsync(audit.AuditLog{
			Action:      "LOGOUT",
			EntityType:  "AUTH",
			UserID:      &reqUser.ID,
			Description: h.ptr("User logged out: " + reqUser.Email),
			IPAddress:   h.ptr(r.RemoteAddr),
			UserAgent:   h.ptr(r.Header.Get("User-Agent")),
		})
	}

	common.RespondSuccess(w, http.StatusOK, "Logged out successfully", nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// Refresh — Fix #4: issue a new access token from a valid refresh token
// ─────────────────────────────────────────────────────────────────────────────

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Refresh token is required", err)
		return
	}

	claims, err := h.jwt.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		common.RespondError(w, http.StatusUnauthorized, "Invalid or expired refresh token", nil)
		return
	}

	// Check the refresh token has not been revoked (e.g. after a logout).
	if h.revoker.IsRevoked(claims.ID) {
		common.RespondError(w, http.StatusUnauthorized, "Refresh token has been revoked", nil)
		return
	}

	// Rotate: revoke the old refresh token and issue a fresh pair.
	h.revoker.Revoke(claims.ID, claims.ExpiresAt.Time)

	// Re-verify current permissions on refresh to capture any administrative changes
	// Pass nil as requester for internal system lookup during refresh
	permSet, err := h.rbac.GetUserPermissions(claims.Subject, nil)
	var effectivePermissions interface{}
	if err == nil {
		effectivePermissions = permSet.EffectivePermissionNames()
	} else {
		effectivePermissions = claims.Permissions
	}

	tokenPair, err := h.jwt.GenerateTokenPair(
		claims.Subject, claims.Username, claims.Email, claims.Role, effectivePermissions,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to issue new tokens", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "Token refreshed", map[string]interface{}{
		"token":        tokenPair.AccessToken,
		"refreshToken": tokenPair.RefreshToken,
		"permissions":   effectivePermissions,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Password flows
// ─────────────────────────────────────────────────────────────────────────────

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	// Fix #11: validate.Struct was missing in the original — now present.
	if err := h.validate.Struct(req); err != nil {
		// Return the same success message even on validation failure to
		// prevent email enumeration.
		common.RespondSuccess(w, http.StatusOK, "If that email exists, a reset link has been sent.", nil)
		return
	}

	u, err := h.userRepo.FindByEmail(strings.ToLower(req.Email))
	if err != nil || u.Status != "ACTIVE" {
		// Always return success — prevents email verification scanning.
		common.RespondSuccess(w, http.StatusOK, "If that email exists, a reset link has been sent.", nil)
		return
	}

	token := uuid.New().String()
	// Fix #15: TTL is now 1 hour, matching what the email template says.
	const resetTokenTTL = 1 * time.Hour
	expires := time.Now().Add(resetTokenTTL)

	if err := h.userRepo.SetPasswordResetToken(u.ID, &token, &expires); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to generate token", err)
		return
	}

	// Fix #14: frontendURL from config, not hardcoded.
	resetLink := h.frontendURL + "/reset-password?token=" + token
	h.mailer.SendPasswordReset(u.Email, u.FirstName, resetLink)

	common.RespondSuccess(w, http.StatusOK, "If that email exists, a reset link has been sent.", nil)
}

type ResetPasswordRequest struct {
	Token       string `json:"token"       validate:"required"`
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request", err)
		return
	}

	actualPassword := req.NewPassword
	if actualPassword == "" {
		actualPassword = req.Password
	}
	if err := h.validatePassword(actualPassword); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	u, err := h.userRepo.FindByResetToken(req.Token)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid or expired reset token", nil)
		return
	}

	hash, err := argon2.HashPassword(actualPassword)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to encrypt password", err)
		return
	}

	u.Password = hash
	u.IsTemporaryPassword = false
	u.ResetToken = nil
	u.ResetTokenExpiry = nil
	if err := h.userRepo.Update(u); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to update password", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "Password reset successfully! You can now log in.", nil)
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" validate:"required"`
	NewPassword     string `json:"newPassword"     validate:"required,min=8"`
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err)
		return
	}
	if err := h.validatePassword(req.NewPassword); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	u, err := h.userRepo.FindByID(reqUser.ID)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "User not found", nil)
		return
	}

	match, err := argon2.CheckPassword(req.CurrentPassword, u.Password)
	if err != nil || !match {
		common.RespondError(w, http.StatusUnauthorized, "Incorrect current password", nil)
		return
	}

	hash, err := argon2.HashPassword(req.NewPassword)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to hash password", err)
		return
	}

	u.Password = hash
	u.IsTemporaryPassword = false
	if err := h.userRepo.Update(u); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to save password", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "Password successfully changed!", nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) ptr(s string) *string { return &s }

func (h *Handler) logFailedLogin(r *http.Request, identifier string) {
	h.auditRepo.LogAsync(audit.AuditLog{
		Action:      "LOGIN_FAILED",
		EntityType:  "AUTH",
		Description: h.ptr("Failed login attempt: " + identifier),
		IPAddress:   h.ptr(r.RemoteAddr),
		UserAgent:   h.ptr(r.Header.Get("User-Agent")),
	})
}

func (h *Handler) logFailedLoginUser(r *http.Request, u *user.User) {
	h.auditRepo.LogAsync(audit.AuditLog{
		Action:      "LOGIN_FAILED",
		EntityType:  "AUTH",
		UserID:      &u.ID,
		Description: h.ptr("Invalid password for user: " + u.Email),
		IPAddress:   h.ptr(r.RemoteAddr),
		UserAgent:   h.ptr(r.Header.Get("User-Agent")),
	})
}

func (h *Handler) validatePassword(password string) error {
	if len(password) < 10 {
		return errors.New("password must be at least 10 characters long")
	}
	var (
		hasUpper   = false
		hasDigit   = false
		hasSpecial = false
	)
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasDigit || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one digit, and one special character")
	}
	return nil
}
