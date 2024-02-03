package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db             *sql.DB
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

type File struct {
	ID      int
	Name    string
	Content string
	Data    []byte
}

func init() {
	// Open the MySQL database
	var err error
	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/file_system")
	if err != nil {
		fmt.Println("Error opening the database:", err)
		return
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

func main() {
	// Serve static files from the 'static' directory
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/create", createHandler)
	http.HandleFunc("/edit", editHandler)
	http.HandleFunc("/save", saveHandler)

	fmt.Println("Server is running on http://localhost:8081")
	http.ListenAndServe(":8081", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve all files from the database
	rows, err := db.Query("SELECT id, name, content FROM files")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error retrieving files:", err)
		return
	}
	defer rows.Close()

	// Create a slice to store the files
	files := make([]*File, 0)

	// Iterate over the rows and populate the files slice
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
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseMultipartForm(10 << 20) // Limit the file size to 10MB

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

		// Create a new file entry in the database
		result, err := db.Exec("INSERT INTO files (name, content, data) VALUES (?, ?, ?)", fileName, string(fileContent), fileContent)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error inserting file into the database:", err)
			return
		}

		// Retrieve the generated ID of the new file
		fileID, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error retrieving last insert ID:", err)
			return
		}

		// Redirect to the edit page for the newly created file
		http.Redirect(w, r, fmt.Sprintf("/edit?id=%d", fileID), http.StatusSeeOther)
		return
	}

	err := tmpl.ExecuteTemplate(w, "upload.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {
	fileIDStr := r.URL.Query().Get("id")
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Retrieve the file from the database
	row := db.QueryRow("SELECT id, name, content, data FROM files WHERE id = ?", fileID)
	file := &File{}
	err = row.Scan(&file.ID, &file.Name, &file.Content, &file.Data)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
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

		// Update the file content in the database
		_, err = db.Exec("UPDATE files SET content = ? WHERE id = ?", fileContent, fileID)

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Error updating file content:", err)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
