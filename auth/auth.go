package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var err error

func signupPage(res http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		username := req.FormValue("username")
		password := req.FormValue("password")

		var user string

		err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)
		if err != nil && err != sql.ErrNoRows {
			log.Println(err)
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		switch {
		case err == sql.ErrNoRows:
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				log.Println(err)
				http.Error(res, "Server error, unable to create your account.", 500)
				return
			}

			_, err = db.Exec("INSERT INTO users(id, username, password) VALUES(?, ?, ?)", 0, username, hashedPassword)
			if err != nil {
				log.Println(err)
				http.Error(res, "Server error, unable to create your account.", 500)
				return
			}

			// Redirect to login page after successful signup
			http.Redirect(res, req, "templates/login.html", http.StatusSeeOther)
			return
		default:
			http.Redirect(res, req, "/", http.StatusSeeOther)
		}
	} else {
		http.ServeFile(res, req, "./signup.html")
	}
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		username := req.FormValue("username")
		password := req.FormValue("password")

		var databaseUsername string
		var databasePassword string

		err := db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&databaseUsername, &databasePassword)

		if err != nil {
			http.Redirect(res, req, "/login", 301)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
		if err != nil {
			http.Redirect(res, req, "/login", 301)
			return
		}

		res.Write([]byte("Hello" + databaseUsername))
	} else {
		http.ServeFile(res, req, "./login.html")
	}
}

func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "templates/index.html")
}

func main() {
	db, err = sql.Open("mysql", "root:root@tcp(localhost:3306)/new")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/", homePage)

	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/templates/", http.StripPrefix("/templates/", fs))

	http.ListenAndServe(":8080", nil)
}
