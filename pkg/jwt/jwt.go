package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CustomClaims matches the existing JWT payload structure.
type CustomClaims struct {
	Username    string      `json:"username"`
	Email       string      `json:"email"`
	Role        string      `json:"role"`
	Permissions interface{} `json:"permissions"`
	TokenType   string      `json:"tokenType"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair holds both tokens returned on login.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	// JTI values are stored server-side for revocation; expose them so the
	// caller can persist them if needed.
	AccessJTI  string
	RefreshJTI string
}

type TokenProvider struct {
	accessSecret      []byte
	refreshSecret     []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
}

func NewTokenProvider(accessSecret, refreshSecret string, accessExpiryHours, refreshExpiryDays int) *TokenProvider {
	return &TokenProvider{
		accessSecret:      []byte(accessSecret),
		refreshSecret:     []byte(refreshSecret),
		accessExpiration:  time.Duration(accessExpiryHours) * time.Hour,
		refreshExpiration: time.Duration(refreshExpiryDays) * 24 * time.Hour,
	}
}

// GenerateTokenPair issues a new access + refresh token pair.
// Each token has a unique JTI so either can be individually revoked.
func (tp *TokenProvider) GenerateTokenPair(userID, username, email, role string, permissions interface{}) (TokenPair, error) {
	accessJTI := uuid.NewString()
	refreshJTI := uuid.NewString()

	accessToken, err := tp.signToken(userID, username, email, role, permissions, "access", accessJTI, tp.accessSecret, tp.accessExpiration)
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, err := tp.signToken(userID, username, email, role, permissions, "refresh", refreshJTI, tp.refreshSecret, tp.refreshExpiration)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessJTI:    accessJTI,
		RefreshJTI:   refreshJTI,
	}, nil
}

// ValidateAccessToken parses and validates an access token.
func (tp *TokenProvider) ValidateAccessToken(tokenString string) (*CustomClaims, error) {
	claims, err := tp.parseToken(tokenString, tp.accessSecret)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "access" {
		return nil, errors.New("token is not an access token")
	}
	return claims, nil
}

// ValidateRefreshToken parses and validates a refresh token.
func (tp *TokenProvider) ValidateRefreshToken(tokenString string) (*CustomClaims, error) {
	claims, err := tp.parseToken(tokenString, tp.refreshSecret)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}
	return claims, nil
}

// GetJTI extracts the JTI from a token string without full validation.
// Used when revoking a token on logout — we still need the JTI even if
// the token is seconds away from expiry.
func (tp *TokenProvider) GetJTI(tokenString string) (string, error) {
	// NOTE: We parse without validation here because we only need the JTI.
	// The token was already validated by the middleware on this request.
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || claims.ID == "" {
		return "", errors.New("could not extract JTI from token")
	}
	return claims.ID, nil
}

func (tp *TokenProvider) signToken(
	userID, username, email, role string,
	permissions interface{},
	tokenType, jti string,
	secret []byte,
	expiry time.Duration,
) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		Username:    username,
		Email:       email,
		Role:        role,
		Permissions: permissions,
		TokenType:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(secret)
}

func (tp *TokenProvider) parseToken(tokenString string, secret []byte) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid jwt token")
}
