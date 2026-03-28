package sme

import "time"

// SME represents the database entity exactly.
// Fields matching Java's @Convert are stored explicitly as encrypted Base64 strings.
type SME struct {
	ID                   string     `db:"id" json:"id"`
	BusinessName         string     `db:"business_name" json:"businessName"` // Encrypted in DB
	OwnerName            string     `db:"owner_name" json:"ownerName"`       // Encrypted in DB
	Phone                string     `db:"phone" json:"phone"`                // Encrypted in DB
	Email                *string    `db:"email" json:"email"`                // Encrypted in DB
	IDNumber             *string    `db:"id_number" json:"idNumber"`         // Encrypted in DB
	BusinessNameHash     *string    `db:"business_name_hash" json:"-"`       // Blind Index
	OwnerNameHash        *string    `db:"owner_name_hash" json:"-"`          // Blind Index
	PhoneHash            *string    `db:"phone_hash" json:"-"`               // Blind Index
	EmailHash            *string    `db:"email_hash" json:"-"`               // Blind Index
	IDNumberHash         *string    `db:"id_number_hash" json:"-"`           // Blind Index
	BusinessPermitNumber *string    `db:"business_permit_number" json:"businessPermitNumber"`
	Gender               string     `db:"gender" json:"gender"` // MALE, FEMALE, OTHER
	Category             string     `db:"category" json:"category"`
	SubCategory          *string    `db:"sub_category" json:"subCategory"`
	PWD                  string     `db:"pwd" json:"pwd"` // YES, NO
	SubCounty            string     `db:"sub_county" json:"subCounty"`
	Ward                 string     `db:"ward" json:"ward"`
	MarketTown           *string    `db:"market_town" json:"marketTown"`
	BusinessAddress      string     `db:"business_address" json:"businessAddress"`
	Status               string     `db:"status" json:"status"` // ACTIVE, PENDING, INACTIVE
	CreatedByID          string     `db:"created_by_id" json:"createdById"`
	UpdatedByID          string     `db:"updated_by_id" json:"updatedById"`
	CreatedAt            time.Time  `db:"created_at" json:"createdAt"`
	UpdatedAt            *time.Time `db:"updated_at" json:"updatedAt,omitempty"`

	CreatorFirstName string `db:"creator_first_name" json:"-"`
	CreatorLastName  string `db:"creator_last_name" json:"-"`
	UpdaterFirstName string `db:"updater_first_name" json:"-"`
	UpdaterLastName  string `db:"updater_last_name" json:"-"`
}
