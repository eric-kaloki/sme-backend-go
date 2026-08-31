package sme

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
)

// Repository struct ...
type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) FindByID(id string) (*SME, error) {
	var sme SME
	err := r.db.Get(&sme, "SELECT * FROM smes WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Return nil, nil for not found simplicity in service
		}
		return nil, err
	}
	return &sme, nil
}

func (r *Repository) Delete(id string) error {
	result, err := r.db.Exec("DELETE FROM smes WHERE id = $1", id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *Repository) Create(s *SME) error {
	query := `
		INSERT INTO smes (
			id, business_name, owner_name, phone, email, id_number,
			business_name_hash, owner_name_hash, phone_hash, email_hash, id_number_hash,
			business_permit_number, gender, category, sub_category, pwd,
			sub_county, ward, market_town, business_address, status,
			created_by_id, updated_by_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21,
			$22, $23, NOW(), NOW()
		) RETURNING created_at, updated_at
	`
	return r.db.QueryRow(
		query,
		s.ID, s.BusinessName, s.OwnerName, s.Phone, s.Email, s.IDNumber,
		s.BusinessNameHash, s.OwnerNameHash, s.PhoneHash, s.EmailHash, s.IDNumberHash,
		s.BusinessPermitNumber, s.Gender, s.Category, s.SubCategory, s.PWD,
		s.SubCounty, s.Ward, s.MarketTown, s.BusinessAddress, s.Status,
		s.CreatedByID, s.UpdatedByID,
	).Scan(&s.CreatedAt, &s.UpdatedAt)
}

// Search queries using exact blind-index matching rather than fuzzy searches.
func (r *Repository) SearchSMEs(emailHash, phoneHash, status, category, subCounty, ward, gender, pwd, sortBy, sortDir string, page, size int) ([]SME, int, error) {
	query := `
		SELECT s.*,
			   u1.first_name AS creator_first_name, u1.last_name AS creator_last_name,
			   u2.first_name AS updater_first_name, u2.last_name AS updater_last_name
		FROM smes s
		LEFT JOIN users u1 ON s.created_by_id = u1.id
		LEFT JOIN users u2 ON s.updated_by_id = u2.id
		WHERE 1=1
	`
	countQuery := "SELECT COUNT(*) FROM smes s WHERE 1=1"

	args := []interface{}{}
	argId := 1

	if emailHash != "" {
		whereClause := fmt.Sprintf(" AND s.email_hash = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, emailHash)
		argId++
	}
	if phoneHash != "" {
		whereClause := fmt.Sprintf(" AND s.phone_hash = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, phoneHash)
		argId++
	}
	if status != "" {
		whereClause := fmt.Sprintf(" AND s.status = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, status)
		argId++
	}
	if category != "" {
		whereClause := fmt.Sprintf(" AND s.category = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, category)
		argId++
	}
	if subCounty != "" {
		whereClause := fmt.Sprintf(" AND s.sub_county = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, subCounty)
		argId++
	}
	if ward != "" {
		whereClause := fmt.Sprintf(" AND s.ward = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, ward)
		argId++
	}
	if gender != "" {
		whereClause := fmt.Sprintf(" AND s.gender = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, gender)
		argId++
	}
	if pwd != "" {
		whereClause := fmt.Sprintf(" AND s.pwd = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, pwd)
		argId++
	}

	var totalElements int
	err := r.db.Get(&totalElements, r.db.Rebind(countQuery), args...)
	if err != nil {
		return nil, 0, err
	}

	allowedSorts := map[string]string{
		"createdAt": "created_at",
		"status":    "status",
		"category":  "category",
	}
	dbSortCol := "s.created_at"
	if col, ok := allowedSorts[sortBy]; ok {
		dbSortCol = "s." + col
	}

	dir := "DESC"
	if strings.ToUpper(sortDir) == "ASC" {
		dir = "ASC"
	}

	query += fmt.Sprintf(" ORDER BY %s %s LIMIT $%d OFFSET $%d", dbSortCol, dir, argId, argId+1)
	args = append(args, size, page*size)

	var smes []SME
	err = r.db.Select(&smes, r.db.Rebind(query), args...)
	return smes, totalElements, err
}

// ----------------------------------------------------
// Analytics & Dashboard Queries
// ----------------------------------------------------

func (r *Repository) GetStatsOverview(subCounty, ward string) (SmeStatsOverviewResponse, error) {
	var response SmeStatsOverviewResponse

	whereClause := "1=1"
	args := []interface{}{}
	argId := 1

	if subCounty != "" {
		whereClause += fmt.Sprintf(" AND sub_county = $%d", argId)
		args = append(args, subCounty)
		argId++
	}
	if ward != "" {
		whereClause += fmt.Sprintf(" AND ward = $%d", argId)
		args = append(args, ward)
		argId++
	}

	var wg sync.WaitGroup
	errs := make(chan error, 5)

	// Overview counts
	wg.Add(1)
	go func() {
		defer wg.Done()
		q := fmt.Sprintf(`SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'ACTIVE') as active,
			COUNT(*) FILTER (WHERE status = 'PENDING') as pending,
			COUNT(*) FILTER (WHERE status = 'INACTIVE') as inactive
		FROM smes WHERE %s`, whereClause)

		err := r.db.Get(&response.Overview, r.db.Rebind(q), args...)
		if err != nil {
			errs <- err
		}
	}()

	// Category Count
	wg.Add(1)
	go func() {
		defer wg.Done()
		q := fmt.Sprintf("SELECT category, COUNT(*) as count FROM smes WHERE %s GROUP BY category ORDER BY count DESC", whereClause)
		err := r.db.Select(&response.ByCategory, r.db.Rebind(q), args...)
		if err != nil {
			errs <- err
		}
	}()

	// Gender Count
	wg.Add(1)
	go func() {
		defer wg.Done()
		q := fmt.Sprintf("SELECT gender, COUNT(*) as count FROM smes WHERE %s GROUP BY gender", whereClause)
		err := r.db.Select(&response.ByGender, r.db.Rebind(q), args...)
		if err != nil {
			errs <- err
		}
	}()

	// PWD Count
	wg.Add(1)
	go func() {
		defer wg.Done()
		q := fmt.Sprintf("SELECT pwd, COUNT(*) as count FROM smes WHERE %s GROUP BY pwd", whereClause)
		err := r.db.Select(&response.ByPWD, r.db.Rebind(q), args...)
		if err != nil {
			errs <- err
		}
	}()

	// SubCounty / Ward location count
	wg.Add(1)
	go func() {
		defer wg.Done()
		q := fmt.Sprintf("SELECT sub_county, COUNT(*) as count FROM smes WHERE %s GROUP BY sub_county ORDER BY count DESC LIMIT 10", whereClause)
		err := r.db.Select(&response.BySubCounty, r.db.Rebind(q), args...)
		if err != nil {
			errs <- err
		}
	}()

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return response, err
		}
	}

	// Make sure zero-results initialize to empty JSON lists instead of null
	if response.ByCategory == nil {
		response.ByCategory = []CategoryCount{}
	}
	if response.ByGender == nil {
		response.ByGender = []GenderCount{}
	}
	if response.ByPWD == nil {
		response.ByPWD = []PwdCount{}
	}
	if response.BySubCounty == nil {
		response.BySubCounty = []SubCountyCount{}
	}

	return response, nil
}

func (r *Repository) GetDistinctList(column string) ([]string, error) {
	allowedCols := map[string]bool{"category": true, "sub_county": true, "ward": true}
	if !allowedCols[column] {
		return nil, fmt.Errorf("invalid column: %s", column)
	}

	var list []string
	query := fmt.Sprintf("SELECT DISTINCT %s FROM smes WHERE %s IS NOT NULL ORDER BY %s ASC", column, column, column)
	err := r.db.Select(&list, query)
	if list == nil {
		list = []string{}
	}
	return list, err
}

func (r *Repository) Update(s *SME) error {
	query := `
		UPDATE smes SET
			business_name = $2, owner_name = $3, phone = $4, email = $5, id_number = $6,
			business_name_hash = $7, owner_name_hash = $8, phone_hash = $9, email_hash = $10, id_number_hash = $11,
			business_permit_number = $12, gender = $13, category = $14, sub_category = $15, pwd = $16,
			sub_county = $17, ward = $18, market_town = $19, business_address = $20, status = $21,
			updated_by_id = $22, updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`
	return r.db.QueryRow(
		query,
		s.ID, s.BusinessName, s.OwnerName, s.Phone, s.Email, s.IDNumber,
		s.BusinessNameHash, s.OwnerNameHash, s.PhoneHash, s.EmailHash, s.IDNumberHash,
		s.BusinessPermitNumber, s.Gender, s.Category, s.SubCategory, s.PWD,
		s.SubCounty, s.Ward, s.MarketTown, s.BusinessAddress, s.Status,
		s.UpdatedByID,
	).Scan(&s.UpdatedAt)
}
