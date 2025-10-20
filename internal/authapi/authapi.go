package authapi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/backends"
)

type authApiHandler struct {
	token string
	db    backends.AuthStore
}

func (ah authApiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Simple token-based authentication
	if r.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", ah.token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// grab the username, nt-response and challenge from query parameters
	username := r.URL.Query().Get("username")
	ntResponse := r.URL.Query().Get("nt-response")
	challenge := r.URL.Query().Get("challenge")

	// if any parameter is missing, return bad request
	if username == "" || ntResponse == "" || challenge == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	ntKey, err := backends.AuthenticateUser(ah.db, username, ntResponse, challenge)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed for %s: %v", username, err), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "NT_KEY: %s\n", ntKey)
}

func StartServer(ctx context.Context, addr string, db backends.AuthStore, token string) {
	mux := http.NewServeMux()

	mux.Handle("/authenticate", authApiHandler{
		token: token,
		db:    db,
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		log.Printf("[authapi] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[authapi] listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[authapi] failed: %v", err)
	}
}
