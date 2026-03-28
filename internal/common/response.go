package common

import (
	"encoding/json"
	"net/http"
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

// RespondError sends an ApiResponse formatted as an error
func RespondError(w http.ResponseWriter, status int, message, errorDetail string) {
	RespondJSON(w, status, ApiResponse{
		Success: false,
		Message: message,
		Error:   errorDetail,
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
