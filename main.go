package main

import "os"
import "log"
import "embed"
import "strings"
import "net/http"
import "crypto/rand"
import "encoding/hex"
import "html/template"

import "golang.org/x/crypto/bcrypt"

const (
	EnvDev = "dev"
	EnvProd = "prod"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	Domain = getEnv("DOMAIN", "127.0.0.1")
	Port   = getEnv("PORT", "4242")
	Addr   = Domain + ":" + Port

	appEnv string
)

type TemplateData struct {
	IsAuthenticated bool
	Login string
	IsAdmin bool
}

func getEnv(key string, fallback string) string {
	value, exist := os.LookupEnv(key)

	if !exist {
		return fallback
	}

	return value
}

func isDev() bool { return appEnv == EnvDev }
func isProd() bool { return appEnv == EnvProd }

func render(w http.ResponseWriter, name string, data any) {
	var tmpl *template.Template
	var err error

	if isDev() {
		tmpl, err = template.ParseFiles("templates/base.html", "templates/"+name+".html")
	} else {
		tmpl, err = template.ParseFS(templatesFS, "templates/base.html", "templates/"+name+".html")
	}

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to parse templates: %v\n", err)
		return
	}

	err = tmpl.ExecuteTemplate(w, "base", data)

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Printf("Failed to execute template: %v\n", err)
	}
}

func generateSID() (string, error) {
	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	login := strings.TrimSpace(r.FormValue("user"))
	pwd := strings.TrimSpace(r.FormValue("password"))

	if (login == "" || pwd == "") || (len(login) > 32 || len(pwd) > 64) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Printf("LoginForm: %v\n", r.PostForm.Encode())

	user, err := getUser(login)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pwd))

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if oldCookie, err := r.Cookie("sid"); err == nil {
		deleteSession(oldCookie.Value)
	}

	sid, err := generateSID()

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = createSession(sid, login, user.Role)
	if err != nil {
		log.Printf("Failed to create session: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:      "sid",
		Value:     sid,
		HttpOnly:  true,
		Secure:    isProd(),
		SameSite:  http.SameSiteStrictMode,
		Path:      "/",
	})

	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("sid")

	if err == nil {
		deleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:      "sid",
		Value:     "",
		HttpOnly:  true,
		Secure:    isProd(),
		SameSite:  http.SameSiteStrictMode,
		Path:      "/",
		MaxAge:    -1,
	})

	w.WriteHeader(http.StatusOK)
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("sid")

	if err != nil {
		return false
	}

	_, _, err = getSesssion(cookie.Value)
	return err == nil
}

func templateData(r *http.Request) TemplateData {
	cookie, err := r.Cookie("sid")

	if err != nil {
		return TemplateData{}
	}

	login, role, err := getSesssion(cookie.Value)

	if err != nil {
		return TemplateData{}
	}

	isAdmin := false

	if role == "admin" {
		isAdmin = true
	}

	return TemplateData{IsAuthenticated: true, Login: login, IsAdmin: isAdmin}
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	render(w, "login", nil)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	data := templateData(r)

	if !data.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	render(w, "admin", data)
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	data := templateData(r)

	if !data.IsAuthenticated {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	render(w, "user", data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data := TemplateData{}

	cookie, err := r.Cookie("sid")

	if err == nil {
		login, role, err := getSesssion(cookie.Value)

		isAdmin := false

		if role == "admin" {
			isAdmin = true
		}

		if err == nil {
			data.IsAuthenticated = true
			data.Login = login
			data.IsAdmin = isAdmin
		}
	}

	render(w, "index", data)
}

func main() {
	appEnv = getEnv("APP_ENV", "dev")

	initDB()
	seedDB()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("GET /login", handleLoginPage)
	http.HandleFunc("POST /login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/user", handleUser)

	if isDev() {
		log.Printf("Starting in %v mode\n", appEnv)
	}

	log.Printf("Starting server at: http://%v\n", Addr)
	err := http.ListenAndServe(Addr, nil)

	if err != nil {
		log.Printf("Failed to start server: %v\n", err)
	}
}
