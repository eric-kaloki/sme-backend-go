package common

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// ApiResponse mimics the existing Java ApiResponse structure
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// RespondJSON sends a JSON response with the specified status code
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success":false,"message":"Internal Server Error","error":"failed to marshal response"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

// RespondError sends an ApiResponse formatted as an error.
// In production, internal server errors (500+) are sanitized to prevent information leakage.
func RespondError(w http.ResponseWriter, status int, message string, err error) {
	errorDetail := ""
	if err != nil {
		errorDetail = err.Error()
	}

	// ALWAYS log the full internal error server-side for debugging
	if err != nil {
		log.Printf("[ERROR] Status: %d, Message: %s, Detail: %v", status, message, err)
	}

	displayError := errorDetail

	// Simple sanitization for production to prevent DB/system leak
	if os.Getenv("GO_ENV") == "production" || os.Getenv("GO_ENV") == "staging" {
		if status >= http.StatusInternalServerError {
			displayError = "An internal server error occurred. Please contact support if this persists."
		} else {
			// Even for 400s, let's strip common DB driver prefixes just in case
			if strings.Contains(displayError, "pq: ") || strings.Contains(displayError, "sql: ") {
				displayError = "A database error occurred while processing the request."
			}
		}
	}

	RespondJSON(w, status, ApiResponse{
		Success: false,
		Message: message,
		Error:   displayError,
	})
}

// RespondSuccess sends an ApiResponse formatted as a success
func RespondSuccess(w http.ResponseWriter, status int, message string, data interface{}) {
	RespondJSON(w, status, ApiResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}
