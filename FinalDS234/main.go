package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	sessionName = "file_system_session"
	sessionKey  = []byte("your-secret-key")
	store       = sessions.NewCookieStore(sessionKey)
	updateFile  = make(chan File)
	createFile  = make(chan int)
)
var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan Message)
var (
	db             *sql.DB
	postgresDB     *sql.DB
	files          = make(map[int]*File)
	mutex          sync.Mutex
	tmpl           *template.Template
	createTableSQL = `
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name TEXT,
        content TEXT
    );
    `
)

type User struct {
	ID       int
	Username string
	password string
}
type Message struct {
	Action  string `json:"action"`
	Content string `json:"content"`
}
type File struct {
	ID      int
	Name    string
	Content string
	Data    []byte
}
type Edit struct {
	ID        int
	Document  string
	User      string
	Content   string
	Timestamp time.Time
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func init() {
	// Open the MySQL database
	var err error
	db, err = sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/file_system")
	if err != nil {
		fmt.Println("Error opening the database:", err)
		return
	}
	// Open the PostgreSQL database
	postgresDB, err = sql.Open("postgres", "host=127.0.0.1 port=5432 user=postgres password=root dbname=file_system sslmode=disable")
	if err != nil {
		fmt.Println("Error opening the PostgreSQL database:", err)
		return
	}
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400, // Session expires in 24 hours
		HttpOnly: true,
	}
	// Create files table if not exists
	_, err = db.Exec(createTableSQL)
	if err != nil {
		fmt.Println("Error creating the table:", err)
		return
	}

	// Parse HTML templates
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
}
func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer conn.Close()

	// Register new client
	clients[conn] = true

	// Listen for incoming messages
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println(err)
			delete(clients, conn)
			break
		}
		broadcast <- msg
	}
}

func authenticate(username, password string) bool {

	row := db.QueryRow("SELECT password FROM users WHERE username = ?", username)
	var hashedPassword string
	err := row.Scan(&hashedPassword)
	if err != nil {
		row = postgresDB.QueryRow("SELECT password FROM users WHERE username = $1", username)
		err = row.Scan(&hashedPassword)
		if err != nil {
			return false
		}
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
func main() {
	go func() {
		for {
			select {
			case msg := <-broadcast:
				// Broadcast regular WebSocket messages
				for client := range clients {
					err := client.WriteJSON(msg)
					if err != nil {
						log.Println(err)
						client.Close()
						delete(clients, client)
					}
				}
			case updatedFile := <-updateFile:
				// Broadcast file update messages
				for client := range clients {
					err := client.WriteJSON(Message{
						Action:  "file_update",
						Content: updatedFile.Content,
					})
					if err != nil {
						log.Println(err)
						client.Close()
						delete(clients, client)
					}
				}
			case newFileID := <-createFile:
				// Broadcast file creation messages
				for client := range clients {
					err := client.WriteJSON(Message{
						Action:  "file_create",
						Content: strconv.Itoa(newFileID),
					})
					if err != nil {
						log.Println(err)
						client.Close()
						delete(clients, client)
					}
				}
			}
		}
	}()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	http.HandleFunc("/create", createHandler)
	http.HandleFunc("/edit", editHandler)
	http.HandleFunc("/save", saveHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/view", viewHandler)
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/file/view", fileViewHandler)
	http.HandleFunc("/ws", handleConnections)
	fmt.Println("Server is running on http://localhost:8081")
	http.ListenAndServe(":8081", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query("SELECT id, name, content FROM files")
	if err != nil {
		postgresRows, err := postgresDB.Query("SELECT id, name, content FROM files")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving files from PostgreSQL:", err)
			return
		}
		defer postgresRows.Close()

		files := make([]*File, 0)

		for postgresRows.Next() {
			file := &File{}
			err := postgresRows.Scan(&file.ID, &file.Name, &file.Content)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				fmt.Println("Error scanning file row from PostgreSQL:", err)
				return
			}
			files = append(files, file)
		}
		err = postgresRows.Err()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error iterating over file rows from PostgreSQL:", err)
			return
		}

		// Pass the files data to the template for rendering
		data := struct {
			Files []*File
		}{
			Files: files,
		}

		err = tmpl.ExecuteTemplate(w, "index.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error executing template:", err)
			return
		}
	} else {
		defer rows.Close()

		files := make([]*File, 0)
		for rows.Next() {
			file := &File{}
			err := rows.Scan(&file.ID, &file.Name, &file.Content)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				fmt.Println("Error scanning file row:", err)
				return
			}
			files = append(files, file)
		}
		err = rows.Err()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error iterating over file rows:", err)
			return
		}

		// Pass the files data to the template for rendering
		data := struct {
			Files []*File
		}{
			Files: files,
		}

		err = tmpl.ExecuteTemplate(w, "index.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error executing template:", err)
			return
		}
		session, _ := store.Get(r, sessionName)
		authenticated := session.Values["authenticated"]
		if authenticated == nil || authenticated.(bool) != true {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}
}
func fileViewHandler(w http.ResponseWriter, r *http.Request) {
	fileIDStr := r.URL.Query().Get("id")
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Retrieve the file from the database
	row := db.QueryRow("SELECT id, name, content FROM files WHERE id = ?", fileID)
	file := &File{}
	err = row.Scan(&file.ID, &file.Name, &file.Content)
	if err != nil {
		// Try retrieving the file from the PostgreSQL database if not found in MySQL
		postgresRow := postgresDB.QueryRow("SELECT id, name, content FROM files WHERE id = $1", fileID)
		err = postgresRow.Scan(&file.ID, &file.Name, &file.Content)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
	}

	// Render the file content in a read-only format
	data := struct {
		File *File
	}{
		File: file,
	}

	err = tmpl.ExecuteTemplate(w, "file_view.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseMultipartForm(10 << 20)

		fileName := r.FormValue("fileName")
		file, _, err := r.FormFile("fileContent")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving file from form:", err)
			return
		}
		defer file.Close()

		fileContent, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error reading file content:", err)
			return
		}

		txMySQL, err := db.Begin()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting MySQL transaction:", err)
			return
		}

		txPostgreSQL, err := postgresDB.Begin()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting PostgreSQL transaction:", err)
			txMySQL.Rollback()
			return
		}

		result, err := txMySQL.Exec("INSERT INTO files (name, content, data) VALUES (?, ?, ?)", fileName, string(fileContent), fileContent)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error inserting file into the MySQL database:", err)
			txMySQL.Rollback()
			txPostgreSQL.Rollback()
			return
		}

		_, err = txPostgreSQL.Exec("INSERT INTO files (name, content, data) VALUES ($1, $2, $3)", fileName, string(fileContent), fileContent)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error inserting file into the PostgreSQL database:", err)
			txMySQL.Rollback()
			txPostgreSQL.Rollback()
			return
		}

		err = txMySQL.Commit()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing MySQL transaction:", err)
			txPostgreSQL.Rollback()
			return
		}

		err = txPostgreSQL.Commit()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing PostgreSQL transaction:", err)
			return
		}

		fileID, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving last insert ID:", err)
			return
		}

		createFile <- int(fileID)

		http.Redirect(w, r, fmt.Sprintf("/index"), http.StatusSeeOther)
		return
	}

	err := tmpl.ExecuteTemplate(w, "upload.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
	session, _ := store.Get(r, sessionName)
	authenticated := session.Values["authenticated"]
	if authenticated == nil || authenticated.(bool) != true {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error hashing password:", err)
			return
		}

		// Start a transaction for both
		txMySQL, err := db.Begin()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting MySQL transaction:", err)
			return
		}

		txPostgreSQL, err := postgresDB.Begin()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting PostgreSQL transaction:", err)
			txMySQL.Rollback()
			return
		}

		_, err = txMySQL.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, string(hashedPassword), "user")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error inserting user into the MySQL database:", err)
			txMySQL.Rollback()
			txPostgreSQL.Rollback()
			return
		}

		_, err = txPostgreSQL.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", username, string(hashedPassword), "user")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error inserting user into the PostgreSQL database:", err)
			txMySQL.Rollback()
			txPostgreSQL.Rollback()
			return
		}

		err = txMySQL.Commit()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing MySQL transaction:", err)
			txPostgreSQL.Rollback()
			return
		}

		err = txPostgreSQL.Commit()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing PostgreSQL transaction:", err)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err := tmpl.ExecuteTemplate(w, "signup.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if authenticate(username, password) {
			isAdmin := checkAdmin(username)

			session, _ := store.Get(r, sessionName)
			session.Values["authenticated"] = true

			if isAdmin {
				session.Values["role"] = "admin"
				session.Save(r, w)
				http.Redirect(w, r, "/index", http.StatusSeeOther)
				return
			} else {
				session.Values["role"] = "user"
				session.Save(r, w)
				http.Redirect(w, r, "/view", http.StatusSeeOther)
				return
			}
		}

		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	err := tmpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		// fmt.Println("Error executing template:", err)
		return
	}
	return
}

func checkAdmin(username string) bool {
	var role string
	err := db.QueryRow("SELECT role FROM users WHERE username=?", username).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {

			return false
		}
		log.Println("MySQL Error:", err)

		err = postgresDB.QueryRow("SELECT role FROM users WHERE username=?", username).Scan(&role)
		if err != nil {
			if err == sql.ErrNoRows {

				return false
			}
			log.Println("PostgreSQL Error:", err)
			// Error occurred while retrieving role from PostgreSQL, assume not an admin
			return false
		}
	}

	return role == "admin"
}
func viewHandler(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query("SELECT id, name, content FROM files")
	if err != nil {

		fmt.Println("Error retrieving files from MySQL:", err)

		// Retrieve all files from PostgreSQL
		pgRows, pgErr := postgresDB.Query("SELECT id, name, content FROM files")
		if pgErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving files from PostgreSQL:", pgErr)
			return
		}
		defer pgRows.Close()

		// Create a slice to store the files
		files := make([]*File, 0)

		// Iterate over the PostgreSQL rows and populate the files slice
		for pgRows.Next() {
			file := &File{}
			err := pgRows.Scan(&file.ID, &file.Name, &file.Content)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				fmt.Println("Error scanning PostgreSQL file row:", err)
				return
			}
			files = append(files, file)
		}
		pgErr = pgRows.Err()
		if pgErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error iterating over PostgreSQL file rows:", pgErr)
			return
		}

		// Pass the files data to the template for rendering
		data := struct {
			Files []*File
		}{
			Files: files,
		}

		err := tmpl.ExecuteTemplate(w, "view.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error executing template:", err)
			return
		}
		return
	} else {
		defer rows.Close()

		files := make([]*File, 0)

		for rows.Next() {
			file := &File{}
			err := rows.Scan(&file.ID, &file.Name, &file.Content)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				fmt.Println("Error scanning file row:", err)
				return
			}
			files = append(files, file)
		}
		err = rows.Err()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error iterating over file rows:", err)
			return
		}

		// Pass the files data to the template for rendering
		data := struct {
			Files []*File
		}{
			Files: files,
		}

		err = tmpl.ExecuteTemplate(w, "view.html", data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error executing template:", err)
			return
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	session.Values["authenticated"] = false
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func editHandler(w http.ResponseWriter, r *http.Request) {
	fileIDStr := r.URL.Query().Get("id")
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	row := db.QueryRow("SELECT id, name, content, data FROM files WHERE id = ?", fileID)
	file := &File{}
	err = row.Scan(&file.ID, &file.Name, &file.Content, &file.Data)
	if err != nil {
		// File not found in MySQL, try retrieving from PostgreSQL
		pgRow := postgresDB.QueryRow("SELECT id, name, content, data FROM files WHERE id = $1", fileID)
		file := &File{}
		err = pgRow.Scan(&file.ID, &file.Name, &file.Content, &file.Data)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
	}

	err = tmpl.ExecuteTemplate(w, "edit.html", file)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()

		fileIDStr := r.FormValue("fileID")
		fileID, err := strconv.Atoi(fileIDStr)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		fileContent := r.FormValue("fileContent")
		// Start a transaction for MySQL
		mysqlTx, err := db.Begin()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting MySQL transaction:", err)
			return
		}

		// Start a transaction for PostgreSQL
		pgTx, err := postgresDB.Begin()
		if err != nil {
			mysqlTx.Rollback()
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error starting PostgreSQL transaction:", err)
			return
		}

		// Update the file content in MySQL
		_, err = mysqlTx.Exec("UPDATE files SET content = ? WHERE id = ?", fileContent, fileID)
		if err != nil {
			mysqlTx.Rollback()
			pgTx.Rollback()
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error updating file content in MySQL:", err)
			return
		}

		// Update the file content in PostgreSQL
		_, err = pgTx.Exec("UPDATE files SET content = $1 WHERE id = $2", fileContent, fileID)
		if err != nil {
			mysqlTx.Rollback()
			pgTx.Rollback()
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error updating file content in PostgreSQL:", err)
			return
		}

		// Commit the transactions
		err = mysqlTx.Commit()
		if err != nil {
			pgTx.Rollback()
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing MySQL transaction:", err)
			return
		}

		err = pgTx.Commit()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error committing PostgreSQL transaction:", err)
			return
		}

		// Retrieve the updated file from MySQL
		mysqlRow := db.QueryRow("SELECT id, name, content, data FROM files WHERE id = ?", fileID)
		updatedFile := &File{}
		err = mysqlRow.Scan(&updatedFile.ID, &updatedFile.Name, &updatedFile.Content, &updatedFile.Data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving updated file from MySQL:", err)
			return
		}

		updateFile <- *updatedFile

		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get the file ID from the form
		fileIDStr := r.FormValue("fileID")
		fileID, err := strconv.Atoi(fileIDStr)
		if err != nil {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}

		// Use a wait group to ensure both deletions are completed before proceeding
		var wg sync.WaitGroup
		wg.Add(2)

		// Delete the file from MySQL
		go func() {
			_, err := db.Exec("DELETE FROM files WHERE id = ?", fileID)
			if err != nil {
				fmt.Println("Error deleting file from MySQL:", err)
			}
			wg.Done()
		}()

		// Delete the file from PostgreSQL
		go func() {
			// Log the SQL query for debugging
			sqlQuery := "DELETE FROM files WHERE id = $1"
			_, err := postgresDB.Exec(sqlQuery, fileID)
			fmt.Println("Deleting fileID:", fileID)
			fmt.Println("SQL Query:", sqlQuery)
			if err != nil {
				fmt.Println("Error deleting file from PostgreSQL:", err)
				fmt.Println("SQL Query:", sqlQuery)
			}
			wg.Done()
		}()

		wg.Wait() // Wait for both deletions to complete

		// Broadcast a deletion message to all connected clients
		broadcast <- Message{
			Action:  "file_delete",
			Content: strconv.Itoa(fileID),
		}

		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
