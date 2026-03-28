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

// GetUserFromContext is a helper to securely retrieve the user from context
func GetUserFromContext(ctx context.Context) *AuthenticatedUser {
	user, ok := ctx.Value(UserContextKey).(*AuthenticatedUser)
	if !ok {
		return nil
	}
	return user
}
