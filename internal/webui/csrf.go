package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

const csrfCookieName = "admin_csrf"
const csrfFieldName = "csrf_token"

type csrfCtxKey struct{}

// generateCSRFToken returns a cryptographically random, URL-safe token.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// csrfMiddleware implements stateless CSRF protection using the
// double-submit-cookie pattern: a random token is stored in a cookie and
// must be echoed back in a hidden form field on every state-changing request.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(csrfCookieName); err == nil {
			token = c.Value
		}
		if token == "" {
			newToken, err := generateCSRFToken()
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			token = newToken
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/admin",
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteLaxMode,
			})
		}

		if !safeMethod(r.Method) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Error parsing form", http.StatusBadRequest)
				return
			}
			sent := r.PostFormValue(csrfFieldName)
			if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), csrfCtxKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfToken retrieves the CSRF token stored on the request context.
func csrfToken(r *http.Request) string {
	if token, ok := r.Context().Value(csrfCtxKey{}).(string); ok {
		return token
	}
	return ""
}

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}
