package sme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	return &Handler{
		service:  service,
		validate: validator.New(),
	}
}

func (h *Handler) CreateSME(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil { return }

	var req SmeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Validation error", err.Error())
		return
	}

	creator := &user.User{ID: reqUser.ID, Role: reqUser.Role}
	smeEntity, err := h.service.CreateSME(req, creator)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to create SME", err.Error())
		return
	}

	common.RespondSuccess(w, http.StatusCreated, "SME created successfully", mapToResponse(smeEntity))
}

func (h *Handler) GetAllSMEs(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil { return }

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, err := strconv.Atoi(q.Get("size"))
	if err != nil || size == 0 { size = 10 }

	// Use EXACT matching via plain search terms -> blind indexes
	smes, total, err := h.service.SearchSMEs(
		q.Get("email"), q.Get("phone"), q.Get("status"), q.Get("category"), q.Get("subCounty"),
		"", "", "", q.Get("sortBy"), q.Get("sortDir"), page, size, &user.User{ID: reqUser.ID, Role: reqUser.Role},
	)

	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error retrieving SMEs", err.Error())
		return
	}

	responses := make([]SmeResponse, len(smes))
	for i, s := range smes { responses[i] = mapToResponse(&s) }

	totalPages := total / size
	if total%size > 0 { totalPages++ }

	common.RespondSuccess(w, http.StatusOK, "SMEs retrieved", map[string]interface{}{
		"content": responses, 
		"page": page, 
		"size": size, 
		"totalElements": total, 
		"totalPages": totalPages, 
		"first": page == 0,
		"last": page >= totalPages - 1,
		"numberOfElements": len(responses),
		"empty": len(responses) == 0,
	})
}

// ----------------------------------------------------
// Analytics & Dashboard Handlers
// ----------------------------------------------------

func (h *Handler) GetStatsOverview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stats, err := h.service.GetStatsOverview(q.Get("subCounty"), q.Get("ward"))
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to retrieve stats", err.Error())
		return
	}
	common.RespondSuccess(w, http.StatusOK, "Statistics overview retrieved successfully", stats)
}

func (h *Handler) GetAvailableCategories(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableCategories()
	if err != nil { common.RespondError(w, http.StatusInternalServerError, "Error", err.Error()) ; return }
	common.RespondSuccess(w, http.StatusOK, "Categories retrieved successfully", list)
}

func (h *Handler) GetAvailableSubCounties(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableSubCounties()
	if err != nil { common.RespondError(w, http.StatusInternalServerError, "Error", err.Error()) ; return }
	common.RespondSuccess(w, http.StatusOK, "Sub-counties retrieved successfully", list)
}

func (h *Handler) GetAvailableWards(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.GetAvailableWards()
	if err != nil { common.RespondError(w, http.StatusInternalServerError, "Error", err.Error()) ; return }
	common.RespondSuccess(w, http.StatusOK, "Wards retrieved successfully", list)
}

func (h *Handler) ExportSMEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" { format = "csv" }

	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil { return }

	// Fetch up to 100,000 SMEs matching filters
	// SearchSMEs(email, phone, status, category, subCounty, ward, gender, pwd, sortBy, sortDir, page, size, reqUser)
	responses, _, err := h.service.SearchSMEs(
		"", q.Get("searchTerm"), q.Get("status"), q.Get("category"), q.Get("subCounty"), q.Get("ward"),
		q.Get("gender"), q.Get("pwd"), "createdAt", "DESC", 0, 100000, &user.User{ID: reqUser.ID, Role: reqUser.Role},
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error exporting SMEs", err.Error())
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
	if format == "" { format = "csv" }

	stats, err := h.service.GetStatsOverview(q.Get("subCounty"), q.Get("ward"))
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to retrieve stats", err.Error())
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
	for _, v := range stats.ByCategory { catRows = append(catRows, []string{v.Category, fmt.Sprintf("%d", v.Count)}) }
	sheets = append(sheets, export.SheetData{Name: "By Category", Headers: []string{"Category", "Count"}, Rows: catRows})

	// Gender
	var genRows [][]string
	for _, v := range stats.ByGender { genRows = append(genRows, []string{v.Gender, fmt.Sprintf("%d", v.Count)}) }
	sheets = append(sheets, export.SheetData{Name: "By Gender", Headers: []string{"Gender", "Count"}, Rows: genRows})

	// PWD
	var pwdRows [][]string
	for _, v := range stats.ByPWD { pwdRows = append(pwdRows, []string{v.PWD, fmt.Sprintf("%d", v.Count)}) }
	sheets = append(sheets, export.SheetData{Name: "By PWD", Headers: []string{"PWD Status", "Count"}, Rows: pwdRows})

	// SubCounty
	var subRows [][]string
	for _, v := range stats.BySubCounty { subRows = append(subRows, []string{v.SubCounty, fmt.Sprintf("%d", v.Count)}) }
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

