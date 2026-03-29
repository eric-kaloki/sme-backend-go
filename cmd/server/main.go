package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/machakos/sme-backend-go/config"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/auth"
	internalMiddleware "github.com/machakos/sme-backend-go/internal/middleware"
	"github.com/machakos/sme-backend-go/internal/sme"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/crypto"
	"github.com/machakos/sme-backend-go/pkg/database"
	"github.com/machakos/sme-backend-go/pkg/jwt"
	"github.com/machakos/sme-backend-go/pkg/resend"
)

func main() {
	cfg := config.LoadConfig()
	// Fail-fast if encryption secrets are invalid instead of panicking later.
	if err := crypto.ValidateKey(cfg.EncryptionSecretKey); err != nil {
		log.Fatalf("FATAL: Encryption configuration error: %v", err)
	}
	// 1. Connect database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 2. Init packages & repos
	userRepo := user.NewRepository(db)
	auditRepo := audit.NewRepository(db)

	// Fix #3/#4: TokenProvider now takes separate access and refresh secrets + TTLs.
	jwtProvider := jwt.NewTokenProvider(
		cfg.JWTSecret,
		cfg.RefreshTokenSecret,
		cfg.JWTExpirationHours,
		cfg.RefreshTokenExpiryDays,
	)

	// Fix #3: In-memory revocation store. Replace with Redis implementation
	// if the service is ever scaled to multiple instances.
	revocationStore := jwt.NewRevocationStore()

	// 3. Init handlers
	mailer := resend.NewMailer(cfg.ResendAPIKey, cfg.ResendEnabled, cfg.ResendFromEmail, cfg.ResendFromName)

	// Fix #3/#4/#14: Handler now receives revoker and frontendURL.
	authHandler := auth.NewHandler(userRepo, auditRepo, jwtProvider, revocationStore, mailer, cfg.FrontendURL)

	// 4. Router setup
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(internalMiddleware.SecurityHeaders)
	r.Use(internalMiddleware.RequestLogger)
	r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(100, 1*time.Minute))

	// Fix #13: CORS origins from environment variable, not hardcoded.
	allowedOrigins := parseAllowedOrigins(cfg.AllowedOrigins)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders: []string{"Link"},
		MaxAge:         300,
	}))

	// Health check — unauthenticated, required by Render
	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"UP"}`))
	})

	// Public auth routes — tightly rate limited
	r.Route("/api/auth", func(r chi.Router) {
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/login", authHandler.Login)
		r.Post("/logout", authHandler.Logout)        // Fix #3: logout now revokes tokens
		r.Post("/refresh", authHandler.RefreshToken) // Fix #4: real refresh endpoint
		r.Post("/forgot-password", authHandler.ForgotPassword)
		r.Post("/reset-password", authHandler.ResetPassword)
		r.Group(func(r chi.Router) {
			// Fix #3: middleware now takes revocationStore
			r.Use(auth.RequireAuth(jwtProvider, revocationStore))
			r.Post("/change-password", authHandler.ChangePassword)
		})
	})

	// Private routes — all require a valid, non-revoked access token
	apiRouter := chi.NewRouter()
	apiRouter.Use(auth.RequireAuth(jwtProvider, revocationStore))

	// User routes
	userService := user.NewService(userRepo, auditRepo, mailer)
	userHandler := user.NewHandler(userService)

	apiRouter.Route("/users", func(r chi.Router) {
		r.Post("/", userHandler.CreateUser)
		r.Get("/", userHandler.GetAllUsers)
		r.Get("/{id}", userHandler.GetUserById)
		r.Put("/{id}", userHandler.UpdateUser)
		r.Post("/{id}/reset-password", userHandler.ResetPassword)
		r.Delete("/{id}", userHandler.DeleteUser)
	})

	// SME routes — Fix #2: service now enforces role checks on Create/Update/Delete
	smeRepo := sme.NewRepository(db)
	smeService := sme.NewService(smeRepo, auditRepo, cfg.EncryptionSecretKey, cfg.BlindIndexKey)
	smeHandler := sme.NewHandler(smeService)

	apiRouter.Route("/sme", func(r chi.Router) {
		r.Post("/", smeHandler.CreateSME)
		r.Get("/", smeHandler.GetAllSMEs)
		r.Delete("/{id}", smeHandler.DeleteSME)
		r.Put("/{id}", smeHandler.UpdateSME)
		r.Get("/export", smeHandler.ExportSMEs)

		r.Get("/stats/overview", smeHandler.GetStatsOverview)
		r.Get("/filters/categories", smeHandler.GetAvailableCategories)
		r.Get("/filters/subcounties", smeHandler.GetAvailableSubCounties)
		r.Get("/filters/wards", smeHandler.GetAvailableWards)
	})

	apiRouter.Route("/analytics", func(r chi.Router) {
		r.Get("/export", smeHandler.ExportAnalytics)
	})

	// Audit routes
	auditHandler := audit.NewHandler(auditRepo)
	apiRouter.Route("/audit", func(r chi.Router) {
		r.Post("/log-export", auditHandler.LogExport)
		r.Get("/user/{userId}", userHandler.GetUserAuditLogs)
	})

	apiRouter.Route("/audit-logs", func(r chi.Router) {
		r.Get("/", auditHandler.GetAuditLogs)
		r.Get("/export", auditHandler.ExportAuditLogs)
	})

	r.Mount("/api", apiRouter)

	// 5. Start server
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Printf("Machakos SME Go Backend running on port %s (env: %s)", cfg.Port, cfg.Environment)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// 6. Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutdown signal received — draining connections...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	auditRepo.Close()
	db.Close()
	log.Println("Server and database connections closed cleanly.")
}

// parseAllowedOrigins splits a comma-separated ALLOWED_ORIGINS string.
// Trims whitespace from each entry to be robust against formatting variation.
func parseAllowedOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}
