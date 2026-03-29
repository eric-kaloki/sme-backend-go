package user

import (
	"encoding/json"
	"net/http"
	"regexp"
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
	v := validator.New()

	// Complex regexes are better handled as named validators to avoid tag parsing issues with pipes (|)
	v.RegisterValidation("kenya_phone", func(fl validator.FieldLevel) bool {
		phone := fl.Field().String()
		re := regexp.MustCompile(`^(01|07)\d{8}|(2547|2541)\d{8}$`)
		return re.MatchString(phone)
	})

	v.RegisterValidation("kenya_id", func(fl validator.FieldLevel) bool {
		id := fl.Field().String()
		re := regexp.MustCompile(`^\d{7,8}$`)
		return re.MatchString(id)
	})

	return &Handler{
		service:  service,
		validate: v,
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
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err)
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
	if err != nil || size <= 0 {
		size = 10
	}
	if size > 100 {
		size = 100
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
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation", err)
		return
	}
	u, err := h.service.UpdateUser(id, req, &User{ID: reqUser.ID, Role: reqUser.Role})
	h.handleServiceError(w, err, "User updated", u, http.StatusOK)
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
			common.RespondError(w, http.StatusForbidden, "Forbidden", nil)
			return
		}
		if err == ErrUserNotFound {
			common.RespondError(w, http.StatusNotFound, "User not found", nil)
			return
		}
		if err == ErrConflict {
			common.RespondError(w, http.StatusConflict, "Conflict", nil)
			return
		}
		if err == ErrBadRequest {
			common.RespondError(w, http.StatusBadRequest, "Bad Request", nil)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Internal Error", err)
		return
	}
	if data != nil {
		common.RespondSuccess(w, status, successMsg, mapToResponse(data))
	} else {
		common.RespondSuccess(w, status, successMsg, nil)
	}
}

func (h *Handler) GetUserAuditLogs(w http.ResponseWriter, r *http.Request) {
	userId := chi.URLParam(r, "userId")
	if userId == "" {
		common.RespondError(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, err := strconv.Atoi(q.Get("limit"))
	if err != nil || size == 0 {
		size = 10
	}

	data, err := h.service.GetUserAuditLogs(userId, page, size)
	if err != nil {
		h.handleServiceError(w, err, "", nil, http.StatusOK)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "User audit logs retrieved", data)
}
