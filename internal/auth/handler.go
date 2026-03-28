package auth

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/argon2"
	"github.com/machakos/sme-backend-go/pkg/jwt"
	"github.com/machakos/sme-backend-go/pkg/resend"
	"net/http"
	"time"
)

type Handler struct {
	userRepo  *user.Repository
	auditRepo *audit.Repository
	jwt       *jwt.TokenProvider
	mailer    *resend.Mailer
	validate  *validator.Validate
}

func NewHandler(userRepo *user.Repository, auditRepo *audit.Repository, jwtProv *jwt.TokenProvider, mailer *resend.Mailer) *Handler {
	return &Handler{
		userRepo:  userRepo,
		auditRepo: auditRepo,
		jwt:       jwtProv,
		mailer:    mailer,
		validate:  validator.New(),
	}
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
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
	CustomPermissions *string    `json:"customPermissions"`
	LastLogin         *time.Time `json:"lastLogin"`
}

type LoginResponse struct {
	Token                  string       `json:"token"`
	RefreshToken           string       `json:"refreshToken"`
	Admin                  UserResponse `json:"admin"`
	SessionTimeout         int          `json:"sessionTimeout"`
	RequiresPasswordChange bool         `json:"requiresPasswordChange"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	u, err := h.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Fallback: try to find by username in case the user typed their username into the "Email" field
		u, err = h.userRepo.FindByUsername(req.Email)
		if err != nil {
			h.auditRepo.LogAsync(audit.AuditLog{
				Action:      "LOGIN_FAILED",
				EntityType:  "AUTH",
				Description: h.ptr("Failed login attempt: " + req.Email),
				IPAddress:   h.ptr(r.RemoteAddr),
				UserAgent:   h.ptr(r.Header.Get("User-Agent")),
			})
			common.RespondError(w, http.StatusUnauthorized, "Invalid email, username, or password", "")
			return
		}
	}

	// Verify password
	match, err := argon2.CheckPassword(req.Password, u.Password)
	if err != nil || !match {
		h.auditRepo.LogAsync(audit.AuditLog{
			Action:      "LOGIN_FAILED",
			EntityType:  "AUTH",
			UserID:      &u.ID,
			Description: h.ptr("Invalid password for user: " + u.Email),
			IPAddress:   h.ptr(r.RemoteAddr),
			UserAgent:   h.ptr(r.Header.Get("User-Agent")),
		})
		common.RespondError(w, http.StatusUnauthorized, "Invalid email or password", "")
		return
	}

	// Important: Check user status
	if u.Status != "ACTIVE" {
		common.RespondError(w, http.StatusForbidden, "User account is not active", "user_status_"+u.Status)
		return
	}

	// Generate JWT claims
	var customPerms interface{}
	if u.CustomPermissions != nil && *u.CustomPermissions != "" {
		json.Unmarshal([]byte(*u.CustomPermissions), &customPerms) // Parse JSON string from DB to inject cleanly into JWT
	}

	tokenString, err := h.jwt.GenerateToken(u.ID, u.Username, u.Email, u.Role, customPerms)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to generate token", err.Error())
		return
	}

	// AUDIT LOG
	h.auditRepo.LogAsync(audit.AuditLog{
		Action:      "LOGIN",
		EntityType:  "AUTH",
		UserID:      &u.ID,
		Description: h.ptr("User logged in: " + u.Email),
		IPAddress:   h.ptr(r.RemoteAddr),
		UserAgent:   h.ptr(r.Header.Get("User-Agent")),
	})

	// Update last login asynchronously
	go h.userRepo.UpdateLastLogin(u.ID)

	response := LoginResponse{
		Token:                  tokenString,
		RefreshToken:           tokenString,  // TODO: different TTL for refresh token
		SessionTimeout:         24 * 60 * 60, // 24 hours in seconds
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
			CustomPermissions: u.CustomPermissions,
			LastLogin:         u.LastLogin,
		},
	}

	common.RespondSuccess(w, http.StatusOK, "Login successful", response)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// In a stateless JWT setup, logout is mainly handled client-side.
	user := common.GetUserFromContext(r.Context())
	if user != nil {
		h.auditRepo.LogAsync(audit.AuditLog{
			Action:      "LOGOUT",
			EntityType:  "AUTH",
			UserID:      &user.ID,
			Description: h.ptr("User logged out: " + user.Email),
			IPAddress:   h.ptr(r.RemoteAddr),
			UserAgent:   h.ptr(r.Header.Get("User-Agent")),
		})
	}

	common.RespondSuccess(w, http.StatusOK, "Logged out successfully", nil)
}

func (h *Handler) ptr(s string) *string {
	return &s
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}
	u, err := h.userRepo.FindByEmail(req.Email)
	if err != nil || u.Status != "ACTIVE" {
		// Crucial: Always return success to prevent email verification scanning / scamming
		common.RespondSuccess(w, http.StatusOK, "If that email exists, a reset link has been sent.", nil)
		return
	}
	// Generate a secure reset token
	token := uuid.New().String()
	expires := time.Now().Add(10 * time.Minute)
	if err := h.userRepo.SetPasswordResetToken(u.ID, &token, &expires); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to generate token", err.Error())
		return
	}
	resetLink := "http://localhost:8081/reset-password?token=" + token
	h.mailer.SendPasswordReset(u.Email, u.FirstName, resetLink)
	common.RespondSuccess(w, http.StatusOK, "If that email exists, a reset link has been sent.", nil)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	// 1. Unmask the real password from whichever JSON field the frontend used
	actualPassword := req.NewPassword
	if actualPassword == "" {
		actualPassword = req.Password
	}

	// 2. We MUST manually validate the password since it could be in either field
	if len(actualPassword) < 8 {
		common.RespondError(w, http.StatusBadRequest, "Password must be at least 8 characters", "")
		return
	}

	// 3. Validate the token exists and is not expired
	u, err := h.userRepo.FindByResetToken(req.Token)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid or expired reset token", "")
		return
	}

	// 4. Hash the actual password!
	hash, err := argon2.HashPassword(actualPassword)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to encrypt password", err.Error())
		return
	}

	// 5. Clear token to prevent reuse and update user
	u.Password = hash
	u.IsTemporaryPassword = false
	u.ResetToken = nil
	u.ResetTokenExpiry = nil
	if err := h.userRepo.Update(u); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to update password", err.Error())
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Password reset successfully! You can now log in.", nil)
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid JSON payload", err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err.Error())
		return
	}

	u, err := h.userRepo.FindByID(reqUser.ID)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "User not found", "")
		return
	}

	match, err := argon2.CheckPassword(req.OldPassword, u.Password)
	if err != nil || !match {
		common.RespondError(w, http.StatusUnauthorized, "Incorrect old password", "")
		return
	}

	hash, err := argon2.HashPassword(req.NewPassword)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to hash custom password", err.Error())
		return
	}

	u.Password = hash
	u.IsTemporaryPassword = false
	if err := h.userRepo.Update(u); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to save password", err.Error())
		return
	}

	common.RespondSuccess(w, http.StatusOK, "Password successfully changed!", nil)
}
