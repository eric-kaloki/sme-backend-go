package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/machakos/sme-backend-go/config"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/auth"
	"github.com/machakos/sme-backend-go/internal/sme"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/database"
	"github.com/machakos/sme-backend-go/pkg/jwt"
	"github.com/machakos/sme-backend-go/pkg/resend"
)

func main() {
	cfg := config.LoadConfig()

	// 1. Connect database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 2. Init packages & repos
	userRepo := user.NewRepository(db)
	jwtProvider := jwt.NewTokenProvider(cfg.JWTSecret)

	// 3. Init handlers
	authHandler := auth.NewHandler(userRepo, jwtProvider)

	// 4. Router setup
	r := chi.NewRouter()

	// Global Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// CORS matching Spring Boot config
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173", "https://machakoscountysmes-new.vercel.app", "http://localhost:8081"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders: []string{"Link"},
		MaxAge:         300,
	}))

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "UP"}`))
	})

	// Public routes
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/login", authHandler.Login)
		r.Post("/logout", authHandler.Logout)
	})

	// Private routes
	apiRouter := chi.NewRouter()
	apiRouter.Use(auth.RequireAuth(jwtProvider))
	
	// Shared Repositories
	auditRepo := audit.NewRepository(db)

	// User Routes
	userService := user.NewService(userRepo, auditRepo, resend.NewMailer(cfg.ResendAPIKey, cfg.ResendEnabled, cfg.ResendFromEmail, cfg.ResendFromName))
	userHandler := user.NewHandler(userService)
	
	apiRouter.Route("/users", func(r chi.Router) {
		r.Post("/", userHandler.CreateUser)       // POST /api/users
		r.Get("/", userHandler.GetAllUsers)       // GET /api/users
		r.Get("/{id}", userHandler.GetUserById)
		r.Put("/{id}", userHandler.UpdateUser)
		r.Post("/{id}/promote", userHandler.PromoteUser)
		r.Post("/{id}/demote", userHandler.DemoteUser)
		r.Post("/{id}/reset-password", userHandler.ResetPassword)
		r.Delete("/{id}", userHandler.DeleteUser)
	})

	// SME Routes
	smeRepo := sme.NewRepository(db)
	smeService := sme.NewService(smeRepo, auditRepo, cfg.EncryptionSecretKey, cfg.BlindIndexKey)
	smeHandler := sme.NewHandler(smeService)
	
	apiRouter.Route("/sme", func(r chi.Router) {
		r.Post("/", smeHandler.CreateSME)       // POST /api/sme
		r.Get("/", smeHandler.GetAllSMEs)       // GET /api/sme
		r.Get("/export", smeHandler.ExportSMEs) // GET /api/sme/export

		// Analytics & Filters
		r.Get("/stats/overview", smeHandler.GetStatsOverview)
		r.Get("/filters/categories", smeHandler.GetAvailableCategories)
		r.Get("/filters/subcounties", smeHandler.GetAvailableSubCounties)
		r.Get("/filters/wards", smeHandler.GetAvailableWards)
	})

	apiRouter.Route("/analytics", func(r chi.Router) {
		r.Get("/export", smeHandler.ExportAnalytics) // GET /api/analytics/export
	})

	// Audit Logs Route
	auditHandler := audit.NewHandler(auditRepo)
	apiRouter.Route("/audit", func(r chi.Router) {
		r.Post("/log-export", auditHandler.LogExport)
	})

	apiRouter.Route("/audit-logs", func(r chi.Router) {
		r.Get("/", auditHandler.GetAuditLogs)
		r.Get("/export", auditHandler.ExportAuditLogs) // GET /api/audit-logs/export
	})

	r.Mount("/api", apiRouter)

	log.Printf("Machakos SME Go Backend listening on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatal(err)
	}
}
