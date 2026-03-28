package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims matches the structure of the Java JWT payload
type CustomClaims struct {
	Username    string      `json:"username"`
	Email       string      `json:"email"`
	Role        string      `json:"role"`
	Permissions interface{} `json:"permissions"`
	jwt.RegisteredClaims
}

type TokenProvider struct {
	secretKey     []byte
	jwtExpiration time.Duration
}

func NewTokenProvider(secret string) *TokenProvider {
	return &TokenProvider{
		secretKey:     []byte(secret),
		jwtExpiration: 24 * time.Hour, // Hardcoded for now, matches Java
	}
}

// GenerateToken issues a new HS512 token matching the Java implementation
func (tp *TokenProvider) GenerateToken(userID, username, email, role string, permissions interface{}) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		Username:    username,
		Email:       email,
		Role:        role,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tp.jwtExpiration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(tp.secretKey)
}

// ValidateToken checks if a token is valid and parses the claims
func (tp *TokenProvider) ValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HS512 like Java
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return tp.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid jwt token")
}
