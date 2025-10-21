package webui

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func basicAuthMiddleware(next http.Handler) http.Handler {
	htpasswd := os.Getenv("ADMIN_AUTH")
	if htpasswd == "" {
		log.Fatal("ADMIN_AUTH environment variable not set")
	}

	parts := strings.SplitN(htpasswd, ":", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid htpasswd format — must be 'user:hash'")
	}
	username := parts[0]
	hash := []byte(parts[1])

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			unauthorized(w)
			return
		}

		payload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 {
			unauthorized(w)
			return
		}

		user, pass := pair[0], pair[1]
		if user != username || bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil {
			unauthorized(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
