package middleware

import "net/http"

// SecurityHeaders adds baseline HTTP security headers to all responses to protect
// against clickjacking, MIME-sniffing, and other common web vulnerabilities.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent the site from being embedded in iframes (Anti-Clickjacking)
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent the browser from interpreting files as something else (Anti-MIME Sniffing)
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Control how much referrer information is passed to other sites
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Enforce HTTPS for the next year (HSTS)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Enable XSS protection in older browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Restrict where content can be loaded from (Content Security Policy)
		// For an API, we can be quite restrictive.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")

		// Restrict browser features (Permissions Policy)
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		next.ServeHTTP(w, r)
	})
}
