package user

import (
	"time"
)

// User represents the users table in the database
type User struct {
	ID                  string     `db:"id" json:"id"`
	FirstName           string     `db:"first_name" json:"firstName"`
	LastName            string     `db:"last_name" json:"lastName"`
	Email               string     `db:"email" json:"email"`
	Username            string     `db:"username" json:"username"`
	Password            string     `db:"password" json:"-"` // Omit password in JSON
	Phone               *string    `db:"phone" json:"phone"`
	Role                string     `db:"role" json:"role"`
	Status              string     `db:"status" json:"status"`
	IsTemporaryPassword bool       `db:"is_temporary_password" json:"isTemporaryPassword"`
	CustomPermissions   *string    `db:"custom_permissions" json:"customPermissions"`
	LastLogin           *time.Time `db:"last_login" json:"lastLogin"`
	CreatedAt           time.Time  `db:"created_at" json:"createdAt"`
	UpdatedAt           *time.Time `db:"updated_at" json:"updatedAt"`
}
