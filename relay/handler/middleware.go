// middleware.go — HTTP middleware helpers for the AEGIS-SILENTIUM relay.
// No imports from any other relay subpackage; stdlib only.
//
// AUTHORIZED USE ONLY
package handler

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// Logging middleware
// ────────────────────────────────────────────────────────────────────────────

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// LoggingMiddleware logs each request in a structured format.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("[relay] %s %s %d %dB %s %s",
			r.Method, r.URL.Path, rw.status, rw.bytes,
			time.Since(start).Round(time.Millisecond),
			remoteIP(r))
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Rate-limit middleware
// ────────────────────────────────────────────────────────────────────────────

// RateLimitMiddleware rejects requests that exceed the per-IP rate limit.
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := remoteIP(r)
			if !rl.Allow(ip) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Security headers middleware
// ────────────────────────────────────────────────────────────────────────────

// SecurityHeadersMiddleware adds defensive HTTP security headers to all
// responses.  For a relay serving public HTTPS traffic this prevents
// content-type sniffing, click-jacking, and information disclosure.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		// Remove any server identification headers
		h.Del("Server")
		h.Del("X-Powered-By")
		next.ServeHTTP(w, r)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Recovery (panic catcher) middleware
// ────────────────────────────────────────────────────────────────────────────

// RecoveryMiddleware catches panics in downstream handlers and returns a
// generic 500 response rather than crashing the relay process.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[relay] panic recovered: %v  path=%s", rec, r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Method filter middleware
// ────────────────────────────────────────────────────────────────────────────

// MethodFilter returns a middleware that only permits the listed HTTP methods.
// Other methods receive 405 Method Not Allowed.
func MethodFilter(methods ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		allowed[strings.ToUpper(m)] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := allowed[r.Method]; !ok {
				w.Header().Set("Allow", strings.Join(methods, ", "))
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Chain helper
// ────────────────────────────────────────────────────────────────────────────

// Chain applies a sequence of middleware to a handler, outermost first.
//
// Example:
//
//	h := handler.Chain(myHandler,
//	    handler.RecoveryMiddleware,
//	    handler.LoggingMiddleware,
//	    handler.SecurityHeadersMiddleware,
//	)
func Chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// remoteIP extracts the real client IP, honoring X-Forwarded-For when the
// immediate peer is a trusted reverse proxy.
func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
