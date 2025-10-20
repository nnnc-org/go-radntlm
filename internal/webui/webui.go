package webui

import (
	"context"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

func StartServer(ctx context.Context, addr string, db backends.AuthStore, samlConfig SAMLConfig) {
	mux := http.NewServeMux()

	sp, err := setupSAML(samlConfig)
	if err != nil {
		log.Fatalf("[webui] failed to set up SAML: %v", err)
	}

	mux.Handle("/saml/", sp)

	mux.Handle("/", sp.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sp.Session.GetSession(r)
		if err != nil || session == nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		jwtAttributes := session.(samlsp.JWTSessionClaims)
		username := jwtAttributes.Subject

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl, err := template.ParseFiles("internal/webui/templates/passwordform.html")
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.Printf("[webui] template parse error: %v", err)
				return
			}
			tmpl.Execute(w, nil)
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Error parsing form", http.StatusBadRequest)
				log.Printf("[webui] form parse error: %v", err)
				return
			}

			password := r.FormValue("password")
			if password == "" {
				http.Error(w, "Password cannot be empty", http.StatusBadRequest)
				return
			}
			pwdHash := hex.EncodeToString(crypto.GetNTHash(password))
			if err := db.Add(username, pwdHash, true); err != nil {
				http.Error(w, "Error storing password", http.StatusInternalServerError)
				log.Printf("[webui] error adding user %s: %v", username, err)
				return
			}
			log.Printf("[webui] password set for user %s", username)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl, err := template.ParseFiles("internal/webui/templates/success.html")
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.Printf("[webui] template parse error: %v", err)
				return
			}
			tmpl.Execute(w, nil)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

	})))

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		log.Printf("[webui] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[webui] listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[webui] failed: %v", err)
	}
}
