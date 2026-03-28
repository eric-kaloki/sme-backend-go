package user

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

var ErrUserNotFound = errors.New("user not found")

type Repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

// FindByEmail retrieves a user by their email address
func (r *Repository) FindByEmail(email string) (*User, error) {
	var user User
	err := r.db.Get(&user, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByUsername retrieves a user by their username
func (r *Repository) FindByUsername(username string) (*User, error) {
	var user User
	err := r.db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByID retrieves a user by ID
func (r *Repository) FindByID(id string) (*User, error) {
	var user User
	err := r.db.Get(&user, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *Repository) UpdateLastLogin(id string) error {
	_, err := r.db.Exec("UPDATE users SET last_login = NOW() WHERE id = $1", id)
	return err
}

// Create inserts a new user
func (r *Repository) Create(user *User) error {
	query := `
		INSERT INTO users (
			id, first_name, last_name, email, username, password, phone, role, status, is_temporary_password, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW()
		) RETURNING created_at, updated_at
	`
	return r.db.QueryRow(
		query,
		user.ID, user.FirstName, user.LastName, user.Email, user.Username, user.Password, user.Phone, user.Role, user.Status, user.IsTemporaryPassword,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

// Update saves changes to an existing user
func (r *Repository) Update(user *User) error {
	query := `
		UPDATE users SET
			first_name = $1, last_name = $2, email = $3, username = $4, password = $5, phone = $6, role = $7, status = $8, is_temporary_password = $9, custom_permissions = $10, updated_at = NOW()
		WHERE id = $11
		RETURNING updated_at
	`
	return r.db.QueryRow(
		query,
		user.FirstName, user.LastName, user.Email, user.Username, user.Password, user.Phone, user.Role, user.Status, user.IsTemporaryPassword, user.CustomPermissions, user.ID,
	).Scan(&user.UpdatedAt)
}

// SearchUsers performs paginated querying
func (r *Repository) SearchUsers(search, role, status, sortBy, sortDir string, page, size int) ([]User, int, error) {
	query := "SELECT * FROM users WHERE status != 'DELETED'"
	countQuery := "SELECT COUNT(*) FROM users WHERE status != 'DELETED'"
	
	args := []interface{}{}
	argId := 1

	if search != "" {
		searchTerm := "%" + search + "%"
		whereClause := fmt.Sprintf(" AND (first_name ILIKE $%d OR last_name ILIKE $%d OR email ILIKE $%d)", argId, argId, argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, searchTerm)
		argId++
	}

	if role != "" {
		whereClause := fmt.Sprintf(" AND role = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, role)
		argId++
	}

	if status != "" {
		whereClause := fmt.Sprintf(" AND status = $%d", argId)
		query += whereClause
		countQuery += whereClause
		args = append(args, status)
		argId++
	}

	// Calculate Total
	var totalElements int
	err := r.db.Get(&totalElements, r.db.Rebind(countQuery), args...)
	if err != nil {
		return nil, 0, err
	}

	// Sorting
	allowedSorts := map[string]string{
		"createdAt": "created_at",
		"firstName": "first_name",
		"email":     "email",
		"role":      "role",
		"status":    "status",
	}
	dbSortCol := "created_at"
	if col, ok := allowedSorts[sortBy]; ok {
		dbSortCol = col
	}
	
	dir := "DESC"
	if strings.ToUpper(sortDir) == "ASC" {
		dir = "ASC"
	}

	query += fmt.Sprintf(" ORDER BY %s %s LIMIT $%d OFFSET $%d", dbSortCol, dir, argId, argId+1)
	args = append(args, size, page*size)

	var users []User
	err = r.db.Select(&users, r.db.Rebind(query), args...)
	return users, totalElements, err
}
