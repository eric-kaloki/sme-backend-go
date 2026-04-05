package rbac

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/machakos/sme-backend-go/internal/common"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// GetAllPermissions handles GET /api/roles-permissions/permissions
func (h *Handler) GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.service.GetAllPermissions()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to fetch permissions", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "Permissions retrieved successfully", PermissionsListResponse{Permissions: permissions})
}

// GetUserPermissions handles GET /api/roles-permissions/users/{userId}/permissions
func (h *Handler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
	userId := chi.URLParam(r, "userId")
	if userId == "" {
		common.RespondError(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	// Get requester from context for IDOR protection
	requester := common.GetUserFromContext(r.Context())
	if requester == nil {
		common.RespondError(w, http.StatusUnauthorized, "User context not found", nil)
		return
	}

	resp, err := h.service.GetUserPermissions(userId, requester)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			common.RespondError(w, http.StatusForbidden, err.Error(), nil)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to fetch user permissions", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "User permissions retrieved successfully", resp)
}

// UpdateUserPermissions handles POST /api/roles-permissions/users/{userId}/permissions
func (h *Handler) UpdateUserPermissions(w http.ResponseWriter, r *http.Request) {
	userId := chi.URLParam(r, "userId")
	if userId == "" {
		common.RespondError(w, http.StatusBadRequest, "User ID is required", nil)
		return
	}

	var req UpdateUserPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Get requester from context
	updaterRaw := common.GetUserFromContext(r.Context())
	if updaterRaw == nil {
		common.RespondError(w, http.StatusUnauthorized, "User context not found", nil)
		return
	}

	updatedUser, err := h.service.UpdateUserPermissions(userId, req.Action, req.Permissions, updaterRaw)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			common.RespondError(w, http.StatusForbidden, err.Error(), nil)
			return
		}
		if errors.Is(err, ErrBadRequest) {
			common.RespondError(w, http.StatusBadRequest, err.Error(), nil)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to update permissions", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "User permissions updated successfully", updatedUser)
}
