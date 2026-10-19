package webui

import (
	"encoding/hex"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/nnnc-org/go-radntlm/internal/backends"
	"github.com/nnnc-org/go-radntlm/internal/crypto"
)

var adminTmpl = template.Must(
	template.New("admin_users.html").Funcs(template.FuncMap{
		"dec": func(i int) int { return i - 1 },
		"inc": func(i int) int { return i + 1 },
	}).ParseFiles(
		"internal/webui/templates/admin_users.html",
		"internal/webui/templates/add_user.html",
	),
)

func adminMux(db backends.AuthStore) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/", basicAuthMiddleware(csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHandler(w, r, db)
	}))))

	return mux
}

func adminHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	switch r.URL.Path {
	case "/admin", "/admin/":
		adminInterface(w, r, db)
	case "/admin/reset":
		adminResetHandler(w, r, db)
	case "/admin/new":
		adminAddUserHandler(w, r, db)
	case "/admin/delete":
		adminDeleteHandler(w, r, db)
	case "/admin/disable-expiration":
		adminDisableExpirationHandler(w, r, db)
	default:
		http.NotFound(w, r)
	}

}

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
		CSRFToken  string
	}{
		Users: rows, Search: search, Expired: expired, Page: page, TotalPages: totalPages,
		CSRFToken: csrfToken(r),
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
	err := db.Add(username, ntHash, true)
	if err != nil {
		http.Error(w, "Failed to reset password: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=Password+reset+for+"+username, http.StatusSeeOther)
}

func adminDisableExpirationHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Missing username", 400)
		return
	}
	err := db.SetExpiration(username, 0)
	if err != nil {
		http.Error(w, "Failed to disable expiration: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=Expiration+disabled+for+"+username, http.StatusSeeOther)
}

func adminDeleteHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Missing username", 400)
		return
	}
	err := db.Delete(username)
	if err != nil {
		http.Error(w, "Failed to delete user: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=User+"+username+"+deleted", http.StatusSeeOther)
}

func adminAddUserHandler(w http.ResponseWriter, r *http.Request, db backends.AuthStore) {
	type formData struct {
		Email     string
		Error     string
		CSRFToken string
	}
	token := csrfToken(r)

	switch r.Method {
	case "GET":
		adminTmpl.ExecuteTemplate(w, "add_user", formData{CSRFToken: token})
	case "POST":
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		// Basic email validation
		emailRegex := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
		if email == "" || !emailRegex.MatchString(email) {
			adminTmpl.ExecuteTemplate(w, "add_user", formData{
				Email:     email,
				Error:     "Please enter a valid email address.",
				CSRFToken: token,
			})
			return
		}
		if password == "" {
			adminTmpl.ExecuteTemplate(w, "add_user", formData{
				Email:     email,
				Error:     "Password cannot be empty.",
				CSRFToken: token,
			})
			return
		}
		if password != confirm {
			adminTmpl.ExecuteTemplate(w, "add_user", formData{
				Email:     email,
				Error:     "Passwords do not match.",
				CSRFToken: token,
			})
			return
		}

		ntHash := hex.EncodeToString(crypto.GetNTHash(password))
		err := db.Add(email, ntHash, true)
		if err != nil {
			adminTmpl.ExecuteTemplate(w, "add_user", formData{
				Email:     email,
				Error:     "Failed to add user: " + err.Error(),
				CSRFToken: token,
			})
			return
		}
		http.Redirect(w, r, "/admin?msg=User+"+email+"+added", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
