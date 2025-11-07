package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Global database (bad)
var data = make(map[int]User)
var m = &sync.RWMutex{}
var counter = 1 // global id counter

// User struct
type User struct {
	ID        int
	User_Name string // bad naming
	Email     string
	pass      string // unexported, but still bad
}

// Hardcoded secret
var DB_PASS = "SuperSecretPassword123!"

// This function simulates a slow DB connection
func connectToDB() {
	// Leaks secret to logs
	log.Println("Connecting to DB with pass: " + DB_PASS)
	time.Sleep(50 * time.Millisecond) // blocks handler
}

// This handler does too much
func handler(w http.ResponseWriter, r *http.Request) {
	// No method check (e.g., POST), allows GET for state change
	connectToDB()

	// No validation or sanitization
	name := r.URL.Query().Get("name")
	email := r.URL.Query().Get("email")
	pass := r.URL.Query().Get("pass")

	if name == "" || email == "" {
		fmt.Fprintf(w, "error, missing info") // No proper error code
		return
	}

	// Inefficient lock
	m.Lock() // Using full write-lock for a check
	defer m.Unlock()

	// Check for existing user (inefficiently)
	for _, u := range data {
		if u.User_Name == name {
			fmt.Fprintf(w, "user exists") // Bad error
			return
		}
	}

	// Create user
	newUser := User{
		ID:        counter,
		User_Name: name,
		Email:     email,
		pass:      pass, // Storing password in plain text
	}
	data[counter] = newUser
	counter++

	fmt.Fprintf(w, "User created! ID: %d", newUser.ID) // Leaking internal ID
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	connectToDB()

	// Vulnerable to SQLi-like issues (if this were SQL)
	// Here, it's an XSS vulnerability
	userQuery := r.URL.Query().Get("user_name")
	idQuery := r.URL.Query().Get("id")

	// Inefficient lock (should use RLock)
	m.Lock()
	defer m.Unlock()

	if idQuery != "" {
		// No error handling on conversion
		id, _ := strconv.Atoi(idQuery)
		user, ok := data[id]
		if ok {
			// Manual JSON crafting
			fmt.Fprintf(w, "{\"id\": %d, \"name\": \"%s\"}", user.ID, user.User_Name)
			return
		}
	} else if userQuery != "" {
		var foundUser User
		found := false
		for _, u := range data {
			if u.User_Name == userQuery {
				foundUser = u
				found = true
				break
			}
		}

		if !found {
			// Reflected XSS vulnerability
			fmt.Fprintf(w, "User not found: %s", userQuery)
			w.WriteHeader(http.StatusNotFound) // Setting header *after* writing body
			return
		} else {
			// Manual JSON crafting, no content-type
			fmt.Fprintf(w, "{\"id\": %d, \"name\": \"%s\", \"email\": \"%s\"}",
				foundUser.ID, foundUser.User_Name, foundUser.Email)
			return
		}
	}

	fmt.Fprintf(w, "Please provide 'id' or 'user_name'")
}

// bad function name
func list_all_user(w http.ResponseWriter, r *http.Request) {
	connectToDB()

	// Inefficient lock. Using write lock for a read.
	m.Lock()
	defer m.Unlock()

	// Building a giant string. Inefficient.
	var result = "["
	for _, u := range data {
		// Manual JSON crafting, again.
		userStr := fmt.Sprintf("{\"id\": %d, \"name\": \"%s\"},", u.ID, u.User_Name)
		result += userStr
	}

	// Sloppy string trimming
	if len(data) > 0 {
		result = result[:len(result)-1] // Remove last comma
	}
	result += "]"

	w.Header().Set("Content-Type", "application/json") // One good thing!
	fmt.Fprintf(w, result)                             // But still using Fprintf
}

func main() {
	// Hardcoded port, using DefaultServeMux (bad practice)
	fmt.Println("Server starting on port 9090")      // Log message
	http.HandleFunc("/user/new", handler)            // 'handler' is a terrible name
	http.HandleFunc("/user/get", GetUser)            // Vague
	http.HandleFunc("/users/all", list_all_user)     // inconsistent naming
	log.Fatal(http.ListenAndServe(":9090", nil)) // Mismatched port in log
}