package user

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/machakos/sme-backend-go/internal/common"
)

type Handler struct {
	service  *Service
	validate *validator.Validate
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service:  service,
		validate: validator.New(),
	}
}

// UserResponse mimics the JSON response returned by Java
type UserResponse struct {
	ID                  string     `json:"id"`
	FirstName           string     `json:"firstName"`
	LastName            string     `json:"lastName"`
	Email               string     `json:"email"`
	Username            string     `json:"username"`
	Phone               *string    `json:"phone"`
	Role                string     `json:"role"`
	Status              string     `json:"status"`
	IsTemporaryPassword bool       `json:"isTemporaryPassword"`
	LastLogin           *time.Time `json:"lastLogin"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           *time.Time `json:"updatedAt"`
	Permissions         []string   `json:"permissions"`
}

func mapToResponse(user *User) UserResponse {
	return UserResponse{
		ID:                  user.ID,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		Email:               user.Email,
		Username:            user.Username,
		Phone:               user.Phone,
		Role:                user.Role,
		Status:              user.Status,
		IsTemporaryPassword: user.IsTemporaryPassword,
		LastLogin:           user.LastLogin,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		Permissions:         []string{}, // Add proper permission parsing later if needed
	}
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	creator := common.GetUserFromContext(r.Context())
	if creator == nil {
		return
	}
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err.Error())
		return
	}

	creatorUser := &User{ID: creator.ID, Email: creator.Email, Role: creator.Role}
	userEntity, err := h.service.CreateUser(req, creatorUser)
	h.handleServiceError(w, err, "User created successfully. Login credentials sent.", userEntity, http.StatusCreated)
}

func (h *Handler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, err := strconv.Atoi(q.Get("size"))
	if err != nil || size == 0 {
		size = 10
	}

	users, total, err := h.service.GetAllUsers(q.Get("search"), q.Get("role"), q.Get("status"), q.Get("sortBy"), q.Get("sortDir"), page, size, &User{ID: reqUser.ID, Role: reqUser.Role})
	if err != nil {
		h.handleServiceError(w, err, "", nil, http.StatusOK)
		return
	}

	responses := make([]UserResponse, len(users))
	for i, u := range users {
		responses[i] = mapToResponse(&u)
	}

	totalPages := total / size
	if total%size > 0 {
		totalPages++
	}

	common.RespondSuccess(w, http.StatusOK, "Users retrieved", map[string]interface{}{
		"items": responses, "page": page, "size": size, "totalElements": total, "totalPages": totalPages, "hasNext": page < totalPages-1, "hasPrevious": page > 0,
	})
}

func (h *Handler) GetUserById(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	u, err := h.service.GetUserById(id, &User{ID: reqUser.ID, Role: reqUser.Role})
	h.handleServiceError(w, err, "User retrieved", u, http.StatusOK)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation", err.Error())
		return
	}
	u, err := h.service.UpdateUser(id, req, &User{ID: reqUser.ID, Role: reqUser.Role})
	h.handleServiceError(w, err, "User updated", u, http.StatusOK)
}

func (h *Handler) PromoteUser(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	var req RoleChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	u, err := h.service.PromoteUser(id, req.NewRole, &User{ID: reqUser.ID, Role: reqUser.Role})
	h.handleServiceError(w, err, "User promoted", u, http.StatusOK)
}

func (h *Handler) DemoteUser(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	var req RoleChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	u, err := h.service.DemoteUser(id, req.NewRole, &User{ID: reqUser.ID, Role: reqUser.Role})
	h.handleServiceError(w, err, "User demoted", u, http.StatusOK)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	err := h.service.ResetPassword(id, &User{ID: reqUser.ID, Role: reqUser.Role})
	if err != nil {
		h.handleServiceError(w, err, "", nil, http.StatusOK)
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Password reset successfully. Email sent.", nil)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	id := chi.URLParam(r, "id")
	err := h.service.DeleteUser(id, &User{ID: reqUser.ID, Role: reqUser.Role})
	if err != nil {
		h.handleServiceError(w, err, "", nil, http.StatusOK)
		return
	}
	common.RespondJSON(w, http.StatusOK, map[string]interface{}{})
}

func (h *Handler) handleServiceError(w http.ResponseWriter, err error, successMsg string, data *User, status int) {
	if err != nil {
		if err == ErrForbidden {
			common.RespondError(w, http.StatusForbidden, "Forbidden", "")
			return
		}
		if err == ErrUserNotFound {
			common.RespondError(w, http.StatusNotFound, "User not found", "")
			return
		}
		if err == ErrConflict {
			common.RespondError(w, http.StatusConflict, "Conflict", "")
			return
		}
		if err == ErrBadRequest {
			common.RespondError(w, http.StatusBadRequest, "Bad Request", "")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}
	if data != nil {
		common.RespondSuccess(w, status, successMsg, mapToResponse(data))
	} else {
		common.RespondSuccess(w, status, successMsg, nil)
	}
}
