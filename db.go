package main

import "log"
import "database/sql"

import "golang.org/x/crypto/bcrypt"
import _ "github.com/mattn/go-sqlite3"

var db *sql.DB

func initDB() {
	var err error

	dbPath := getEnv("DB_PATH", "./auth.db")

	db, err = sql.Open("sqlite3", dbPath)

	if err != nil {
		log.Printf("Failed to open '%v' file: %v\n", dbPath, err)
	}

	err = db.Ping()

	if err != nil {
		log.Printf("Failed to ping database: %v\n", err)
	}

	createTables()
}

func createTables() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			login    TEXT    NOT NULL UNIQUE,
			password TEXT    NOT NULL,
			role     TEXT    NOT NULL DEFAULT 'user'
		);

		CREATE TABLE IF NOT EXISTS sessions (
			sid        TEXT    PRIMARY KEY,
			user_login TEXT    NOT NULL,
			user_role  TEXT    NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)

	if err != nil {
		log.Printf("Failed to create tables: %v\n", err)
	}
}

type User struct {
	Login string
	Password string
	Role string
}

var seedUsers = []User{
	{Login: "admin",   Password: "admin123",   Role: "admin"},
	{Login: "alice",   Password: "alice123",   Role: "user"},
	{Login: "bob",     Password: "bob123",     Role: "user"},
	{Login: "charlie", Password: "charlie123", Role: "user"},
	{Login: "diana",   Password: "diana123",   Role: "user"},
}

func seedDB() {
	for _, user := range seedUsers {
		var exists bool

		err := db.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)", user.Login,
		).Scan(&exists)

		if err != nil {
			log.Printf("Failed to query users row: %v\n", err)
			continue
		}

		if exists { continue }

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

		if err != nil {
			log.Printf("Failed to generate user pwd hash: %v\n", err)
			continue
		}

		_, err = db.Exec(
			"INSERT INTO users (login, password, role) VALUES (?, ?, ?)",
			user.Login, string(hash), user.Role,
		)

		if err != nil {
			log.Printf("Failed to insert seed user: %v\n", err)
		}
	}
}

func getUser(login string) (User, error) {
	var user User

	err := db.QueryRow("SELECT login, password, role FROM users WHERE login = ?", login).Scan(&user.Login, &user.Password, &user.Role)

	return user, err
}

func createSession(sid, login, role string) error {
	_, err := db.Exec("INSERT INTO sessions (sid, user_login, user_role) VALUES (?, ?, ?)", sid, login, role)
	return err
}

func getSesssion(sid string) (string, string, error) {
	var login, role string
	err := db.QueryRow("SELECT user_login, user_role FROM sessions WHERE sid = ?", sid).Scan(&login, &role)
	return login, role, err
}

func deleteSession(sid string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE sid = ?", sid)
	return err
}
