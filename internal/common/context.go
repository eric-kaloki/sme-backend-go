package common

import "context"

type userContextKey string

const UserContextKey userContextKey = "user"

type AuthenticatedUser struct {
	ID          string
	Username    string
	Email       string
	Role        string
	Permissions interface{}
}

// HasPermission checks if the user has a specific permission
func (u *AuthenticatedUser) HasPermission(perm string) bool {
	if u.Permissions == nil {
		return false
	}
	
	perms, ok := u.Permissions.([]string)
	if ok {
		for _, p := range perms {
			if p == perm {
				return true
			}
		}
		return false
	}

	// Handle case where it might be []interface{} from JWT
	permsIf, ok := u.Permissions.([]interface{})
	if ok {
		for _, p := range permsIf {
			if ps, ok := p.(string); ok && ps == perm {
				return true
			}
		}
	}

	return false
}

// GetUserFromContext is a helper to securely retrieve the user from context
func GetUserFromContext(ctx context.Context) *AuthenticatedUser {
	user, ok := ctx.Value(UserContextKey).(*AuthenticatedUser)
	if !ok {
		return nil
	}
	return user
}
