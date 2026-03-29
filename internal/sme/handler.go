package sme

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/export"
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

func (h *Handler) CreateSME(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	var req SmeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err)
		return
	}

	creator := &user.User{ID: reqUser.ID, Role: reqUser.Role}
	smeEntity, err := h.service.CreateSME(req, creator)
	if err != nil {
		if err == ErrForbidden {
			common.RespondError(w, http.StatusForbidden, "Forbidden", err)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to create SME", err)
		return
	}

	common.RespondSuccess(w, http.StatusCreated, "SME created successfully", mapToResponse(smeEntity))
}

func (h *Handler) DeleteSME(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		common.RespondError(w, http.StatusBadRequest, "Missing SME ID", errors.New("id path parameter is required"))
		return
	}

	deleter := &user.User{ID: reqUser.ID, Role: reqUser.Role}
	if err := h.service.DeleteSME(id, deleter); err != nil {
		if err == ErrNotFound {
			common.RespondError(w, http.StatusNotFound, "SME not found", err)
			return
		}
		if err == ErrForbidden {
			common.RespondError(w, http.StatusForbidden, "Forbidden", err)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete SME", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "SME deleted successfully", nil)
}

func (h *Handler) UpdateSME(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		common.RespondError(w, http.StatusBadRequest, "Missing SME ID", errors.New("id path parameter is required"))
		return
	}

	var req SmeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err)
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err)
		return
	}

	updater := &user.User{ID: reqUser.ID, Role: reqUser.Role}
	smeEntity, err := h.service.UpdateSME(id, req, updater)
	if err != nil {
		if err == ErrNotFound {
			common.RespondError(w, http.StatusNotFound, "SME not found", err)
			return
		}
		if err == ErrForbidden {
			common.RespondError(w, http.StatusForbidden, "Forbidden", err)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to update SME", err)
		return
	}

	common.RespondSuccess(w, http.StatusOK, "SME updated successfully", mapToResponse(smeEntity))
}

func (h *Handler) GetAllSMEs(w http.ResponseWriter, r *http.Request) {
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

	// Use EXACT matching via plain search terms -> blind indexes
	smes, total, err := h.service.SearchSMEs(
		q.Get("email"), q.Get("phone"), q.Get("status"), q.Get("category"), q.Get("subCounty"),
		"", "", "", q.Get("sortBy"), q.Get("sortDir"), page, size, &user.User{ID: reqUser.ID, Role: reqUser.Role},
	)

	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error retrieving SMEs", err)
		return
	}

	responses := make([]SmeResponse, len(smes))
	for i, s := range smes {
		responses[i] = mapToResponse(&s)
	}

	totalPages := total / size
	if total%size > 0 {
		totalPages++
	}

	common.RespondSuccess(w, http.StatusOK, "SMEs retrieved", map[string]interface{}{
		"content":          responses,
		"page":             page,
		"size":             size,
		"totalElements":    total,
		"totalPages":       totalPages,
		"first":            page == 0,
		"last":             page >= totalPages-1,
		"numberOfElements": len(responses),
		"empty":            len(responses) == 0,
	})
}

// ----------------------------------------------------
// Analytics & Dashboard Handlers
// ----------------------------------------------------

func (h *Handler) GetStatsOverview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stats, err := h.service.GetStatsOverview(q.Get("subCounty"), q.Get("ward"))
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to retrieve stats", err)
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Statistics overview retrieved successfully", stats)
}

func (h *Handler) GetAvailableCategories(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableCategories()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error", err)
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Categories retrieved successfully", list)
}

func (h *Handler) GetAvailableSubCounties(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableSubCounties()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error", err)
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Sub-counties retrieved successfully", list)
}

func (h *Handler) GetAvailableWards(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableWards()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error", err)
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Wards retrieved successfully", list)
}

func (h *Handler) ExportSMEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	// Fetch up to 100,000 SMEs matching filters
	// SearchSMEs(email, phone, status, category, subCounty, ward, gender, pwd, sortBy, sortDir, page, size, reqUser)
	responses, _, err := h.service.SearchSMEs(
		"", q.Get("searchTerm"), q.Get("status"), q.Get("category"), q.Get("subCounty"), q.Get("ward"),
		q.Get("gender"), q.Get("pwd"), "createdAt", "DESC", 0, 100000, &user.User{ID: reqUser.ID, Role: reqUser.Role},
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error exporting SMEs", err)
		return
	}

	headers := []string{"ID", "Business Name", "Owner Name", "Phone", "Email", "ID Number", "Permit", "Gender", "Category", "SubCategory", "PWD", "SubCounty", "Ward", "Status", "Created At"}
	var rows [][]string
	for _, s := range responses {
		rows = append(rows, []string{
			s.ID, s.BusinessName, s.OwnerName, s.Phone, export.FormatStr(s.Email), export.FormatStr(s.IDNumber),
			export.FormatStr(s.BusinessPermitNumber), s.Gender, s.Category, export.FormatStr(s.SubCategory), s.PWD, s.SubCounty, s.Ward, s.Status,
			s.CreatedAt.Format(time.RFC3339),
		})
	}

	dateStr := time.Now().Format("20060102")
	if format == "xlsx" {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"export_smes_%s.xlsx\"", dateStr))
		export.WriteExcel(w, []export.SheetData{{Headers: headers, Rows: rows}})
	} else {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"export_smes_%s.csv\"", dateStr))
		export.WriteCSV(w, headers, rows)
	}
}

func (h *Handler) ExportAnalytics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	stats, err := h.service.GetStatsOverview(q.Get("subCounty"), q.Get("ward"))
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to retrieve stats", err)
		return
	}

	var sheets []export.SheetData

	// Overview
	sheets = append(sheets, export.SheetData{
		Name:    "Overview",
		Headers: []string{"Total", "Active", "Pending", "Inactive"},
		Rows: [][]string{{
			fmt.Sprintf("%d", stats.Overview.Total),
			fmt.Sprintf("%d", stats.Overview.Active),
			fmt.Sprintf("%d", stats.Overview.Pending),
			fmt.Sprintf("%d", stats.Overview.Inactive),
		}},
	})

	// Category
	var catRows [][]string
	for _, v := range stats.ByCategory {
		catRows = append(catRows, []string{v.Category, fmt.Sprintf("%d", v.Count)})
	}
	sheets = append(sheets, export.SheetData{Name: "By Category", Headers: []string{"Category", "Count"}, Rows: catRows})

	// Gender
	var genRows [][]string
	for _, v := range stats.ByGender {
		genRows = append(genRows, []string{v.Gender, fmt.Sprintf("%d", v.Count)})
	}
	sheets = append(sheets, export.SheetData{Name: "By Gender", Headers: []string{"Gender", "Count"}, Rows: genRows})

	// PWD
	var pwdRows [][]string
	for _, v := range stats.ByPWD {
		pwdRows = append(pwdRows, []string{v.PWD, fmt.Sprintf("%d", v.Count)})
	}
	sheets = append(sheets, export.SheetData{Name: "By PWD", Headers: []string{"PWD Status", "Count"}, Rows: pwdRows})

	// SubCounty
	var subRows [][]string
	for _, v := range stats.BySubCounty {
		subRows = append(subRows, []string{v.SubCounty, fmt.Sprintf("%d", v.Count)})
	}
	sheets = append(sheets, export.SheetData{Name: "By SubCounty", Headers: []string{"SubCounty", "Count"}, Rows: subRows})

	dateStr := time.Now().Format("20060102")
	if format == "xlsx" {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"analytics_export_%s.xlsx\"", dateStr))
		export.WriteExcel(w, sheets)
	} else {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"analytics_export_%s.csv\"", dateStr))
		export.WriteStackedCSV(w, sheets)
	}
}
