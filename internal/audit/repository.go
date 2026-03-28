package audit

import (
	"fmt"
	"log"
	"sync"

	"github.com/jmoiron/sqlx"
)

type Repository struct {
	db      *sqlx.DB
	logChan chan AuditLog
	wg      sync.WaitGroup
}

func NewRepository(db *sqlx.DB) *Repository {
	repo := &Repository{
		db:      db,
		logChan: make(chan AuditLog, 100), // Buffered channel for bursts
	}

	// Start background worker
	repo.wg.Add(1)
	go repo.processLogs()

	return repo
}

func (r *Repository) processLogs() {
	defer r.wg.Done()

	query := `
		INSERT INTO audit_logs 
		(id, action, entity_type, entity_id, old_data, new_data, description, ip_address, user_agent, user_id, sme_id, created_at, updated_at) 
		VALUES 
		(gen_random_uuid(), :action, :entity_type, :entity_id, :old_data, :new_data, :description, :ip_address, :user_agent, :user_id, :sme_id, NOW(), NOW())
	`

	for entry := range r.logChan {
		if _, err := r.db.NamedExec(query, entry); err != nil {
			log.Printf("ERROR: Failed to save audit log: %v", err)
		}
	}
}

// LogAsync sends the audit log to a background worker to ensure non-blocking execution.
func (r *Repository) LogAsync(logEntry AuditLog) {
	select {
	case r.logChan <- logEntry:
	default:
		log.Printf("WARNING: Audit log queue full, dropping log: %s", logEntry.Action)
	}
}

// Close gracefully shuts down the background worker, ensuring all pending logs are saved.
func (r *Repository) Close() {
	close(r.logChan)
	r.wg.Wait()
}

func (r *Repository) SearchAuditLogs(action, entityType, userId, entityId, search, sortBy, sortDir string, page, size int) ([]AuditLogResponse, int, error) {
	query := `
		SELECT a.*,
			   u.first_name AS user_first_name, u.last_name AS user_last_name, u.email AS user_email
		FROM audit_logs a
		LEFT JOIN users u ON a.user_id = u.id
		WHERE 1=1
	`
	countQuery := "SELECT COUNT(*) FROM audit_logs a WHERE 1=1"

	args := []interface{}{}
	argId := 1

	if action != "" {
		whereClause := fmt.Sprintf(" AND a.action = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, action)
		argId++
	}
	if entityType != "" {
		whereClause := fmt.Sprintf(" AND a.entity_type = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, entityType)
		argId++
	}
	if userId != "" {
		whereClause := fmt.Sprintf(" AND a.user_id = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, userId)
		argId++
	}
	if entityId != "" {
		whereClause := fmt.Sprintf(" AND a.entity_id = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, entityId)
		argId++
	}

	total := 0
	if err := r.db.Get(&total, r.db.Rebind(countQuery), args...); err != nil {
		return nil, 0, err
	}

	dbSortCol := "a.created_at"
	if sortBy == "action" {
		dbSortCol = "a.action"
	}
	if sortBy == "entityType" {
		dbSortCol = "a.entity_type"
	}

	dir := "DESC"
	if sortDir == "asc" {
		dir = "ASC"
	}

	query += fmt.Sprintf(" ORDER BY %s %s LIMIT $%d OFFSET $%d", dbSortCol, dir, argId, argId+1)
	args = append(args, size, page*size)

	var logs []AuditLogResponse
	err := r.db.Select(&logs, r.db.Rebind(query), args...)
	return logs, total, err
}
