package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL            string
	JWTSecret              string
	RefreshTokenSecret     string // Separate secret for refresh tokens (Fix #4)
	Port                   string
	Environment            string
	FrontendURL            string // Fix #14 — no more hardcoded URLs
	AllowedOrigins         string // Fix #13 — CORS from env
	ResendAPIKey           string
	ResendEnabled          bool
	ResendFromEmail        string
	ResendFromName         string
	EncryptionSecretKey    string
	BlindIndexKey          string
	JWTExpirationHours     int
	RefreshTokenExpiryDays int // Fix #4 — separate refresh TTL
	ShutdownTimeoutSeconds int
}

func LoadConfig() *Config {
	// Load .env file if present; ignore error so prod uses real env vars
	_ = godotenv.Load()

	// ── Required variables — fail fast if missing ──────────────────────────

	dbURL := requireEnv("DATABASE_URL",
		"Set DATABASE_URL to a full postgres connection string with sslmode=require")

	jwtSecret := requireEnv("JWT_SECRET",
		"Set JWT_SECRET to a cryptographically random string (min 32 chars)")

	encryptionKey := requireEnv("ENCRYPTION_SECRET_KEY",
		"Set ENCRYPTION_SECRET_KEY to a base64-encoded AES-256 key")

	blindIndexKey := requireEnv("BLIND_INDEX_KEY",
		"Set BLIND_INDEX_KEY to a base64-encoded HMAC key")

	// REFRESH_TOKEN_SECRET defaults to JWT_SECRET with a suffix if not set,
	// but a dedicated secret is strongly recommended for production.
	refreshSecret := getEnvOrDefault("REFRESH_TOKEN_SECRET", jwtSecret+"_refresh")

	// ── Optional variables with safe defaults ─────────────────────────────

	port := getEnvOrDefault("PORT", "8080")
	env := getEnvOrDefault("GO_ENV", "development")
	frontendURL := getEnvOrDefault("FRONTEND_URL", "http://localhost:8081")
	allowedOrigins := getEnvOrDefault("ALLOWED_ORIGINS", frontendURL)

	return &Config{
		DatabaseURL:            dbURL,
		JWTSecret:              jwtSecret,
		RefreshTokenSecret:     refreshSecret,
		Port:                   port,
		Environment:            env,
		FrontendURL:            frontendURL,
		AllowedOrigins:         allowedOrigins,
		ResendAPIKey:           os.Getenv("RESEND_API_KEY"),
		ResendEnabled:          os.Getenv("RESEND_ENABLED") == "true",
		ResendFromEmail:        getEnvOrDefault("EMAIL_FROM", "noreply@county.go.ke"),
		ResendFromName:         getEnvOrDefault("EMAIL_FROM_NAME", "County SME Management"),
		EncryptionSecretKey:    encryptionKey,
		BlindIndexKey:          blindIndexKey,
		JWTExpirationHours:     getEnvAsInt("JWT_EXPIRATION_HOURS", 1), // Short-lived: 1 hour
		RefreshTokenExpiryDays: getEnvAsInt("REFRESH_TOKEN_EXPIRY_DAYS", 7),
		ShutdownTimeoutSeconds: getEnvAsInt("SHUTDOWN_TIMEOUT_SECONDS", 30),
	}
}

// requireEnv reads a required environment variable and calls log.Fatal if missing.
// This is intentional: missing critical secrets must prevent the server from starting.
func requireEnv(key, hint string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("FATAL: Required environment variable %q is not set. Hint: %s", key, hint)
	}
	return val
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return fallback
}

func getEnvAsInt(name string, defaultVal int) int {
	if valueStr := os.Getenv(name); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultVal
}
