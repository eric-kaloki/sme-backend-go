package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/pkg/jwt"
)

// RequireAuth middleware validates the JWT access token and checks the
// revocation store before allowing the request through.
//
// Fix #3: IsRevoked check ensures logged-out tokens are rejected immediately,
// not just after their natural expiry.
func RequireAuth(jwtProv *jwt.TokenProvider, revoker jwt.Revoker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := extractBearerToken(r)
			if err != nil {
				common.RespondError(w, http.StatusUnauthorized, "Missing or invalid authorization header", nil)
				return
			}

			// Fix #3: Validate as access token only (not refresh).
			claims, err := jwtProv.ValidateAccessToken(tokenString)
			if err != nil {
				common.RespondError(w, http.StatusUnauthorized, "Invalid or expired token", err)
				return
			}

			// Fix #3: Check revocation store — catches explicitly logged-out tokens.
			if revoker.IsRevoked(claims.ID) {
				common.RespondError(w, http.StatusUnauthorized, "Token has been revoked", nil)
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

// RequireAnyRole middleware ensures the authenticated user has one of the allowed roles.
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := common.GetUserFromContext(r.Context())
			if user == nil {
				common.RespondError(w, http.StatusUnauthorized, "User context not found", nil)
				return
			}

			for _, allowedRole := range roles {
				if user.Role == allowedRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			common.RespondError(w, http.StatusForbidden, "You do not have permission to perform this action", errors.New("role_forbidden"))
		})
	}
}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}
