package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// RequestLogger is a custom middleware that logs details about incoming HTTP requests.
// It logs [START] when a request arrives and [END] when it completes, including
// the status code and duration.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer so we can capture the status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Log the beginning of the request
		log.Printf("--> [START] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// In development mode, log the JSON request body for easier debugging.
		isDev := os.Getenv("GO_ENV") == "development" || os.Getenv("GO_ENV") == ""
		logBody := os.Getenv("LOG_REQUEST_BODY") == "true"
		contentType := r.Header.Get("Content-Type")

		// We always log for login/auth routes to see redaction in action,
		// or if the explicit toggle is on for all other routes.
		isAuthRoute := r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/reset-password"

		if isDev && (logBody || isAuthRoute) && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
			if contentType == "application/json" {
				body, err := io.ReadAll(r.Body)
				if err == nil && len(body) > 0 {
					// Mask sensitive fields before logging
					maskedBody := maskSensitiveFields(body)
					output := string(maskedBody)

					// Truncate long bodies for cleaner console (unless it's a small auth payload)
					if len(output) > 250 && !isAuthRoute {
						output = output[:250] + "... [TRUNCATED]"
					}

					log.Printf("    [BODY] %s", output)
				}
				// Restore the original body for the next handlers
				r.Body = io.NopCloser(bytes.NewBuffer(body))
			}
		}

		next.ServeHTTP(ww, r)

		// Log the completion of the request
		log.Printf("<-- [END]   %d %s %s (%s) in %v", ww.Status(), r.Method, r.URL.Path, http.StatusText(ww.Status()), time.Since(start))
	})
}

// maskSensitiveFields redacts sensitive JSON keys before logging.
func maskSensitiveFields(body []byte) []byte {
	var data interface{}
	// Use json.Unmarshal into interface{} to preserve structure
	if err := json.Unmarshal(body, &data); err != nil {
		return body // Not valid JSON, return as is
	}

	// We only care about objects (maps) for masking
	if m, ok := data.(map[string]interface{}); ok {
		sensitiveKeys := []string{"password", "token", "secret", "access_token", "refresh_token"}
		mask(m, sensitiveKeys)
		masked, err := json.Marshal(m)
		if err == nil {
			return masked
		}
	}

	return body
}

// mask recursively masks keys in a map.
func mask(data map[string]interface{}, keys []string) {
	for k, v := range data {
		// Check if the current key is sensitive
		isSensitive := false
		for _, sk := range keys {
			if k == sk {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			data[k] = "[REDACTED]"
			continue
		}

		// Recurse if the value is a map
		if nextMap, ok := v.(map[string]interface{}); ok {
			mask(nextMap, keys)
		}

		// Recurse if the value is a slice of maps
		if nextSlice, ok := v.([]interface{}); ok {
			for _, item := range nextSlice {
				if itemMap, ok := item.(map[string]interface{}); ok {
					mask(itemMap, keys)
				}
			}
		}
	}
}
