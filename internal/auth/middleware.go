package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/pkg/jwt"
)

// RequireAuth middleware verifies the JWT token and attaches user claims to context
func RequireAuth(jwtProv *jwt.TokenProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				common.RespondError(w, http.StatusUnauthorized, "Missing or invalid authorization header", "")
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwtProv.ValidateToken(tokenString)
			if err != nil {
				common.RespondError(w, http.StatusUnauthorized, "Invalid or expired token", err.Error())
				return
			}

			user := &common.AuthenticatedUser{
				ID:          claims.Subject,
				Username:    claims.Username,
				Email:       claims.Email,
				Role:        claims.Role,
				Permissions: claims.Permissions,
			}

			ctx := context.WithValue(r.Context(), common.UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAnyRole middleware ensures the authenticated user has one of the allowed roles
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := common.GetUserFromContext(r.Context())
			if user == nil {
				common.RespondError(w, http.StatusUnauthorized, "User context not found", "")
				return
			}

			hasRole := false
			for _, allowedRole := range roles {
				if user.Role == allowedRole {
					hasRole = true
					break
				}
			}

			if !hasRole {
				common.RespondError(w, http.StatusForbidden, "You do not have permission to perform this action", "role_forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
