package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL        string
	JWTSecret          string
	Port               string
	Environment        string
	ResendAPIKey       string
	ResendEnabled      bool
	ResendFromEmail 	string
	ResendFromName  	string
	EncryptionSecretKey string
	BlindIndexKey       string
}

func LoadConfig() *Config {
	// Ignore error if .env doesn't exist, we fallback to environment variables
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Default to the docker-compose dev database
		dbURL = "postgres://sme_user:county_sme_pass_2024@localhost:5432/sme?sslmode=disable"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is missing!")
	}

	return &Config{
		DatabaseURL:     dbURL,
		JWTSecret:       jwtSecret,
		Port:            port,
		Environment:     getEnvOrDefault("GO_ENV", "development"),
		ResendAPIKey:    os.Getenv("RESEND_API_KEY"),
		ResendEnabled:       os.Getenv("RESEND_ENABLED") == "true",
		ResendFromEmail:     getEnvOrDefault("EMAIL_FROM", "noreply@county.go.ke"),
		ResendFromName:      getEnvOrDefault("EMAIL_FROM_NAME", "County SME Management"),
		EncryptionSecretKey: os.Getenv("ENCRYPTION_SECRET_KEY"),
		BlindIndexKey:       os.Getenv("BLIND_INDEX_KEY"),
	}
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
