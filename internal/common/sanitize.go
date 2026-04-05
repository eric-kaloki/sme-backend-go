package common

import (
	"github.com/microcosm-cc/bluemonday"
)

var strictPolicy = bluemonday.StrictPolicy()

// Sanitize strips all HTML tags from a string to prevent XSS attacks.
func Sanitize(input string) string {
	return strictPolicy.Sanitize(input)
}

// SanitizePtr strips all HTML tags from a string pointer.
func SanitizePtr(input *string) *string {
	if input == nil {
		return nil
	}
	s := strictPolicy.Sanitize(*input)
	return &s
}
