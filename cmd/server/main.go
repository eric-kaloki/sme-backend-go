package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/go-chi/httprate"
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
	mailer := resend.NewMailer(cfg.ResendAPIKey, cfg.ResendEnabled, cfg.ResendFromEmail, cfg.ResendFromName)
	authHandler := auth.NewHandler(userRepo, jwtProvider, mailer)

	// 4. Router setup
	r := chi.NewRouter()

	// Global Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(100, 1*time.Minute))

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
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/login", authHandler.Login)
		r.Post("/logout", authHandler.Logout)
		r.Post("/forgot-password", authHandler.ForgotPassword)
		r.Post("/reset-password", authHandler.ResetPassword)
	})

	// Private routes
	apiRouter := chi.NewRouter()
	apiRouter.Use(auth.RequireAuth(jwtProvider))

	// Shared Repositories
	auditRepo := audit.NewRepository(db)

	// User Routes
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

	// SME Routes
	smeRepo := sme.NewRepository(db)
	smeService := sme.NewService(smeRepo, auditRepo, cfg.EncryptionSecretKey, cfg.BlindIndexKey)
	smeHandler := sme.NewHandler(smeService)

	apiRouter.Route("/sme", func(r chi.Router) {
		r.Post("/", smeHandler.CreateSME)       // POST /api/sme
		r.Get("/", smeHandler.GetAllSMEs)       // GET /api/sme
		r.Delete("/{id}", smeHandler.DeleteSME) // DELETE /api/sme/{id}
		r.Put("/{id}", smeHandler.UpdateSME)    // PUT /api/sme/{id}
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
		// Private Auth Endpoints (Requires JWT)
	apiRouter.Route("/auth", func(r chi.Router) {
		r.Post("/change-password", authHandler.ChangePassword)
	})

	apiRouter.Route("/audit-logs", func(r chi.Router) {
		r.Get("/", auditHandler.GetAuditLogs)
		r.Get("/export", auditHandler.ExportAuditLogs) // GET /api/audit-logs/export
	})

	r.Mount("/api", apiRouter)
	// 5. Build the Server manually for graceful shutdown support
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	// 6. Run the server in a goroutine so it doesn't block
	go func() {
		log.Printf("Machakos SME Go Backend successfully running on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// 7. Wait for an OS interrupt signal (e.g., CTRL+C or Docker shutdown)
	quit := make(chan os.Signal, 1)
	// SIGINT is CTRL+C, SIGTERM is sent by Kubernetes/Docker when tearing down pods
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit // This blocks the main thread until a signal is received
	log.Println("\nShutdown signal received! Shutting down server gracefully...")

	// 8. Give active requests 10 seconds to finish what they are doing
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown aggressively: %v", err)
	}

	// 9. Close the database safely
	db.Close()
	log.Println("Server and Database connections closed successfully.")
}
