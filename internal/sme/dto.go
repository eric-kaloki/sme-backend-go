package sme

import "time"

// Existing DTOs ...
type SmeRequest struct {
	BusinessName         string  `json:"businessName" validate:"required,min=2"`
	OwnerName            string  `json:"ownerName" validate:"required"`
	Phone                string  `json:"phone" validate:"required,regexp=^(01|07)\\d{8}|(2547|2541)\\d{8}$"`
	Email                *string `json:"email,omitempty" validate:"omitempty,email"`
	IDNumber             *string `json:"idNumber,omitempty" validate:"omitempty,regexp=^\\d{7,8}$"`
	BusinessPermitNumber *string `json:"businessPermitNumber,omitempty"`
	Gender               string  `json:"gender" validate:"oneof=MALE FEMALE OTHER"`
	Category             string  `json:"category" validate:"required"`
	SubCategory          *string `json:"subCategory,omitempty"`
	PWD                  string  `json:"pwd" validate:"oneof=YES NO"`
	SubCounty            string  `json:"subCounty" validate:"required"`
	Ward                 string  `json:"ward" validate:"required"`
	MarketTown           *string `json:"marketTown,omitempty"`
	BusinessAddress      string  `json:"businessAddress" validate:"required"`
	Status               string  `json:"status,omitempty"`
}

type SmeResponse struct {
	ID                   string     `json:"id"`
	BusinessName         string     `json:"businessName"`
	OwnerName            string     `json:"ownerName"`
	Phone                string     `json:"phone"`
	Email                *string    `json:"email"`
	IDNumber             *string    `json:"idNumber"`
	BusinessPermitNumber *string    `json:"businessPermitNumber"`
	Gender               string     `json:"gender"`
	Category             string     `json:"category"`
	SubCategory          *string    `json:"subCategory"`
	PWD                  string     `json:"pwd"`
	SubCounty            string     `json:"subCounty"`
	Ward                 string     `json:"ward"`
	MarketTown           *string    `json:"marketTown"`
	BusinessAddress      string     `json:"businessAddress"`
	Status               string     `json:"status"`
	CreatedBy            UserMin    `json:"createdBy"`
	UpdatedBy            UserMin    `json:"updatedBy"`
	CreatedAt            time.Time  `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
}

type UserMin struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

func mapToResponse(s *SME) SmeResponse {
	return SmeResponse{
		ID:                   s.ID,
		BusinessName:         s.BusinessName,
		OwnerName:            s.OwnerName,
		Phone:                s.Phone,
		Email:                s.Email,
		IDNumber:             s.IDNumber,
		BusinessPermitNumber: s.BusinessPermitNumber,
		Gender:               s.Gender,
		Category:             s.Category,
		SubCategory:          s.SubCategory,
		PWD:                  s.PWD,
		SubCounty:            s.SubCounty,
		Ward:                 s.Ward,
		MarketTown:           s.MarketTown,
		BusinessAddress:      s.BusinessAddress,
		Status:               s.Status,
		CreatedBy: UserMin{
			ID:        s.CreatedByID,
			FirstName: s.CreatorFirstName,
			LastName:  s.CreatorLastName,
		},
		UpdatedBy: UserMin{
			ID:        s.UpdatedByID,
			FirstName: s.UpdaterFirstName,
			LastName:  s.UpdaterLastName,
		},
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}

// ----------------------------------------------------
// Analytics DTOs
// ----------------------------------------------------

type SmeOverview struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Pending  int64 `json:"pending"`
	Inactive int64 `json:"inactive"`
}

type CategoryCount struct {
	Category string `json:"category" db:"category"`
	Count    int64  `json:"count" db:"count"`
}

type GenderCount struct {
	Gender string `json:"gender" db:"gender"`
	Count  int64  `json:"count" db:"count"`
}

type PwdCount struct {
	PWD   string `json:"pwd" db:"pwd"`
	Count int64  `json:"count" db:"count"`
}

type SubCountyCount struct {
	SubCounty string `json:"subCounty" db:"sub_county"`
	Count     int64  `json:"count" db:"count"`
}

type SmeStatsOverviewResponse struct {
	Overview    SmeOverview      `json:"overview"`
	ByCategory  []CategoryCount  `json:"byCategory"`
	ByGender    []GenderCount    `json:"byGender"`
	ByPWD       []PwdCount       `json:"byPwd"`
	BySubCounty []SubCountyCount `json:"bySubCounty"`
}
