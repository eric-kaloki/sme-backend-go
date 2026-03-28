package user

type CreateUserRequest struct {
	FirstName string  `json:"firstName" validate:"required,min=2,max=50"`
	LastName  string  `json:"lastName" validate:"required,min=2,max=50"`
	Username  string  `json:"username" validate:"required,min=3,max=30"`
	Email     string  `json:"email" validate:"required,email"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,kenya_phone"`
	Role      string  `json:"role" validate:"required"`
}

type UpdateUserRequest struct {
	FirstName *string `json:"firstName,omitempty" validate:"omitempty,min=2,max=50"`
	LastName  *string `json:"lastName,omitempty" validate:"omitempty,min=2,max=50"`
	Email     *string `json:"email,omitempty" validate:"omitempty,email"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,kenya_phone"`
	Status    *string `json:"status,omitempty"`
	Role      *string `json:"role,omitempty"`
}

type RoleChangeRequest struct {
	NewRole string `json:"newRole" validate:"required"`
}

type UpdatePermissionsRequest struct {
	Action      string   `json:"action" validate:"required,oneof=add remove"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
}
