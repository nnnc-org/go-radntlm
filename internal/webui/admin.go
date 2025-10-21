package webui

import (
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

func adminMux(db backends.AuthStore) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHandler(w, r, db)
	})))

	return mux
}

func adminHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	switch r.URL.Path {
	case "/admin", "/admin/":
		adminInterface(w, r, db)
	case "/admin/reset":
		adminResetHandler(w, r, db)
	default:
		http.NotFound(w, r)
	}

}

var adminTmpl = template.Must(
	template.New("admin_users.html").Funcs(template.FuncMap{
		"dec": func(i int) int { return i - 1 },
		"inc": func(i int) int { return i + 1 },
	}).ParseFiles("internal/webui/templates/admin_users.html"),
)

func adminInterface(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	// Parse query params
	search := r.URL.Query().Get("search")
	expired := r.URL.Query().Get("expired") == "1"
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50
	offset := (page - 1) * pageSize

	users, total, err := db.ListUsers(search, expired, offset, pageSize)
	if err != nil {
		http.Error(w, "Failed to list users: "+err.Error(), 500)
		return
	}
	// Prepare data for template
	type userRow struct {
		Username            string
		Expiration          int64
		Expired             bool
		ExpirationFormatted string
	}
	now := time.Now().Unix()
	var rows []userRow
	for _, u := range users {
		expired := u.Expiration != 0 && u.Expiration < now
		expFmt := ""
		if u.Expiration != 0 {
			expFmt = time.Unix(u.Expiration, 0).Format("2006-01-02 15:04")
		}
		rows = append(rows, userRow{
			Username:            u.Username,
			Expiration:          u.Expiration,
			Expired:             expired,
			ExpirationFormatted: expFmt,
		})
	}
	totalPages := (total + pageSize - 1) / pageSize
	data := struct {
		Users      []userRow
		Search     string
		Expired    bool
		Page       int
		TotalPages int
	}{
		Users: rows, Search: search, Expired: expired, Page: page, TotalPages: totalPages,
	}
	adminTmpl.ExecuteTemplate(w, "admin_users", data)
}

func adminResetHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Missing username or password", 400)
		return
	}
	// Hash password as NT hash
	ntHash := hex.EncodeToString(crypto.GetNTHash(password))
	err := db.Add(username, ntHash, false)
	if err != nil {
		http.Error(w, "Failed to reset password: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=Password+reset+for+"+username, http.StatusSeeOther)
}
