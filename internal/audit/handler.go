package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/pkg/export"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))

	sizeStr := q.Get("size")
	if sizeStr == "" {
		sizeStr = q.Get("limit")
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size == 0 {
		size = 20
	}

	logs, total, err := h.repo.SearchAuditLogs(
		q.Get("action"), q.Get("entityType"), q.Get("userId"), q.Get("entityId"),
		q.Get("search"), q.Get("sortBy"), q.Get("sortDir"), page, size,
	)

	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error retrieving audit logs", err.Error())
		return
	}

	// Map flattened joins to structured pointers
	for i := range logs {
		mapToResponse(&logs[i])
	}

	totalPages := total / size
	if total%size > 0 {
		totalPages++
	}

	common.RespondSuccess(w, http.StatusOK, "Audit logs retrieved successfully", map[string]interface{}{
		"content": logs, "items": logs, "page": page, "size": size, "totalElements": total, "totalPages": totalPages,
		"first": page == 0, "last": page >= totalPages-1, "numberOfElements": len(logs), "empty": len(logs) == 0,
	})
}

func (h *Handler) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	logs, _, err := h.repo.SearchAuditLogs(
		q.Get("action"), q.Get("entityType"), q.Get("userId"), q.Get("entityId"),
		q.Get("search"), q.Get("sortBy"), q.Get("sortDir"), 0, 100000,
	)

	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Error retrieving audit logs", err.Error())
		return
	}

	headers := []string{"ID", "Action", "Entity Type", "Entity ID", "Description", "User Name", "User Email", "Created At"}
	var rows [][]string
	for i := range logs {
		mapToResponse(&logs[i])
		s := logs[i]
		userName := ""
		userEmail := ""
		if s.User != nil {
			userName = fmt.Sprintf("%s %s", s.User.FirstName, s.User.LastName)
			userEmail = s.User.Email
		}

		rows = append(rows, []string{
			s.ID, s.Action, s.EntityType, export.FormatStr(s.EntityID), export.FormatStr(s.Description),
			userName, userEmail, s.CreatedAt.Format(time.RFC3339),
		})
	}

	dateStr := time.Now().Format("20060102")
	if format == "xlsx" {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"export_audit_%s.xlsx\"", dateStr))
		export.WriteExcel(w, []export.SheetData{{Headers: headers, Rows: rows}})
	} else {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"export_audit_%s.csv\"", dateStr))
		export.WriteCSV(w, headers, rows)
	}
}

func (h *Handler) LogExport(w http.ResponseWriter, r *http.Request) {
	reqUser := common.GetUserFromContext(r.Context())
	if reqUser == nil {
		return
	}

	var req LogExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid payload", err.Error())
		return
	}

	metadata := map[string]interface{}{
		"filename":    req.Filename,
		"recordCount": req.RecordCount,
		"filters":     req.Filters,
	}

	metaJSON, _ := json.Marshal(metadata)
	metaStr := string(metaJSON)

	// Since we are logging an export, use the action, entityType, description, etc.
	// Store the metadata inside NewData.
	go h.repo.LogAsync(AuditLog{
		Action:      req.Action,
		EntityType:  req.EntityType,
		Description: &req.Description,
		NewData:     &metaStr,
		UserID:      &reqUser.ID,
	})

	common.RespondSuccess(w, http.StatusOK, "Log export saved", map[string]bool{"success": true})
}
