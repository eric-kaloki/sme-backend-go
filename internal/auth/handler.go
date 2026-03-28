package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/argon2"
	"github.com/machakos/sme-backend-go/pkg/jwt"
)

type Handler struct {
	userRepo *user.Repository
	jwt      *jwt.TokenProvider
	validate *validator.Validate
}

func NewHandler(userRepo *user.Repository, jwtProv *jwt.TokenProvider) *Handler {
	return &Handler{
		userRepo: userRepo,
		jwt:      jwtProv,
		validate: validator.New(),
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
	RefreshToken           string       `json:"refreshToken"` // Just generating a fresh HS512 token for now
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
		if err == user.ErrUserNotFound {
			common.RespondError(w, http.StatusUnauthorized, "Invalid email or password", "")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Database error", err.Error())
		return
	}

	// Verify password
	match, err := argon2.CheckPassword(req.Password, u.Password)
	if err != nil || !match {
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

	// Update last login asynchronously
	go h.userRepo.UpdateLastLogin(u.ID)

	response := LoginResponse{
		Token:                  tokenString,
		RefreshToken:           tokenString, // TODO: different TTL for refresh token
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
	common.RespondSuccess(w, http.StatusOK, "Logged out successfully", nil)
}
