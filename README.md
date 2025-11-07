# Go HTTP API Code Review Assessment

## Overview
This assessment demonstrates common security vulnerabilities, concurrency bugs, and poor practices in a Go HTTP API. The project contains one file:
- `codereview.go` - A deliberately flawed user management API with **8 critical issues**

## The Problem (codereview.go)

The buggy code implements a simple HTTP server that manages users in memory. It provides three endpoints:
- `/user/new` - Creates a new user
- `/user/get` - Retrieves a user by ID or username
- `/users/all` - Lists all users

### What the Code Does
1. Stores users in a global in-memory map `data`
2. Accepts user creation requests with name, email, and password
3. Simulates a database connection with `connectToDB()`
4. Returns user data in JSON format (manually constructed)
5. Uses a mutex for thread safety

**But it contains critical security flaws, concurrency bugs, and architectural problems.**

---

## The Eight Critical Issues

### Issue #1: Hardcoded Secrets & Logging Sensitive Data 🔴 **CRITICAL**
**Location:** Lines 27 and 32

**The Problem:**
```go
var DB_PASS = "SuperSecretPassword123!"  // DANGER: Secret in source code!

func connectToDB() {
    log.Println("Connecting to DB with pass: " + DB_PASS)  // DANGER: Logging secret!
    time.Sleep(50 * time.Millisecond)
}
```

**Why It's Broken:**
- Hardcoded credentials are stored in version control (Git history forever!)
- The password is logged on **every request**, exposing it in application logs
- Anyone with access to the repo or logs can steal the credentials
- This violates **every security best practice** and compliance requirement (PCI-DSS, SOC 2, etc.)

**Impact:**
- 🚨 **Immediate security breach risk**
- Database credentials exposed to anyone with log/repo access
- Cannot rotate credentials without code changes
- Fails security audits automatically

**How to Fix:**
```go
// Read from environment variable
dbPass := os.Getenv("DB_PASS")
if dbPass == "" {
    log.Fatal("DB_PASS environment variable not set")
}

func connectToDB() {
    // Never log secrets - log only non-sensitive context
    log.Println("Attempting database connection...")
    // Use dbPass for actual connection (not shown in logs)
}
```

**Detection:**
```bash
git grep -i "password\|secret\|key" *.go
```

---

### Issue #2: Plaintext Password Storage 🔴 **CRITICAL**
**Location:** Lines 22-26 and 56

**The Problem:**
```go
type User struct {
    ID        int
    User_Name string
    Email     string
    pass      string  // Stored in plain text!
}

// Later in handler:
newUser := User{
    pass: pass,  // Password stored directly from query parameter
}
```

**Why It's Broken:**
- User passwords are stored **without any hashing or encryption**
- If the process memory is dumped or the map is serialized, passwords are exposed
- Any internal breach (memory leak, debug output, logs) reveals all user passwords
- Violates OWASP Top 10 and GDPR requirements

**Impact:**
- 🚨 **Catastrophic data breach** if system is compromised
- Users' passwords exposed (often reused across sites)
- Legal liability and compliance violations
- Instant failure of any security audit

**How to Fix:**
```go
import "golang.org/x/crypto/bcrypt"

type User struct {
    ID           int
    UserName     string
    Email        string
    PasswordHash string  // Store hash, not plaintext
}

// When creating user:
hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
    http.Error(w, "Internal server error", http.StatusInternalServerError)
    return
}

newUser := User{
    PasswordHash: string(hash),  // Store the hash
}

// When verifying password later:
err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(providedPassword))
if err != nil {
    // Password doesn't match
}
```

---

### Issue #3: Concurrent Map Access Without Proper Locking 🔴 **HIGH**
**Location:** Lines 47-61 (handler), 80-82 (GetUser), 123-125 (list_all_user)

**The Problem:**
```go
var data = make(map[int]User)
var m = &sync.RWMutex{}

func handler(w http.ResponseWriter, r *http.Request) {
    m.Lock()  // Write lock acquired
    defer m.Unlock()
    
    // Check existing users (READ operation with WRITE lock!)
    for _, u := range data {
        if u.User_Name == name {
            fmt.Fprintf(w, "user exists")
            return
        }
    }
    // ... create user
}

func GetUser(w http.ResponseWriter, r *http.Request) {
    m.Lock()  // WRONG: Using write lock for read operation!
    defer m.Unlock()
    // ... only reads from data
}
```

**Why It's Broken:**
- Uses **write locks (`Lock()`) for read-only operations**
- This blocks ALL other goroutines unnecessarily (readers AND writers)
- Kills concurrency - only one request can execute at a time
- `sync.RWMutex` exists specifically to allow multiple concurrent readers!

**Impact:**
- 🚨 **Severe performance degradation** under load
- API becomes a bottleneck (serializes all requests)
- Poor scalability - can't handle concurrent users
- Wastes the benefits of Go's concurrency

**How to Fix:**
```go
// For READ operations (GetUser, list_all_user):
func GetUser(w http.ResponseWriter, r *http.Request) {
    m.RLock()  // Use read lock - allows concurrent readers
    defer m.RUnlock()
    
    user, ok := data[id]
    m.RUnlock()  // Release ASAP, before I/O
    
    if ok {
        // Do JSON encoding outside lock
        json.NewEncoder(w).Encode(user)
    }
}

// For WRITE operations (handler - creating user):
func handler(w http.ResponseWriter, r *http.Request) {
    // First, check if user exists with read lock
    m.RLock()
    _, exists := data[name]
    m.RUnlock()
    
    if exists {
        http.Error(w, "user exists", http.StatusConflict)
        return
    }
    
    // Then acquire write lock only for the write
    m.Lock()
    data[counter] = newUser
    counter++
    m.Unlock()
}
```

**Detection:**
```bash
go run -race .  # Race detector will flag misuse
```

---

### Issue #4: Blocking Sleep in Request Handler 🟡 **MEDIUM**
**Location:** Line 33

**The Problem:**
```go
func connectToDB() {
    log.Println("Connecting to DB with pass: " + DB_PASS)
    time.Sleep(50 * time.Millisecond)  // Blocks every single request!
}

// Called on EVERY request:
func handler(w http.ResponseWriter, r *http.Request) {
    connectToDB()  // Adds 50ms to every request
    // ...
}
```

**Why It's Broken:**
- Every request sleeps for 50ms **unnecessarily**
- This is meant to simulate a slow DB, but it's blocking the request goroutine
- In production, this would be a connection pool or async operation
- Adds artificial latency to every single API call

**Impact:**
- ⚠️ **Increased tail latency** (minimum 50ms per request)
- Reduced throughput
- Poor user experience
- Wastes goroutine time

**How to Fix:**
```go
// Option 1: Remove the sleep (it's fake anyway for demo)
func connectToDB() {
    // In production, use a connection pool that's already connected
    // No need to "connect" on every request
}

// Option 2: If you need to simulate latency for testing, use context
func connectToDB(ctx context.Context) error {
    select {
    case <-time.After(50 * time.Millisecond):
        return nil
    case <-ctx.Done():
        return ctx.Err()  // Respects cancellation
    }
}
```

---

### Issue #5: No HTTP Method Validation 🟡 **MEDIUM**
**Location:** Line 37 (handler function)

**The Problem:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    // No method check!
    // Accepts GET, POST, PUT, DELETE, PATCH...
    connectToDB()
    
    // Creates/modifies state with ANY HTTP method
    name := r.URL.Query().Get("name")
    // ...
}
```

**Why It's Broken:**
- State-changing operations (creating users) should use POST or PUT
- Currently accepts **GET requests with query parameters** to create users
- GET requests should be idempotent and cacheable (this violates HTTP spec)
- Opens CSRF attack vectors (GET requests can be triggered via `<img>` tags)

**Impact:**
- ⚠️ **Security vulnerability** (CSRF)
- Violates REST principles and HTTP semantics
- Breaks browser caching assumptions
- Poor API design

**How to Fix:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Enforce POST for state changes
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Parse from request body, not query parameters
    var req struct {
        Name     string `json:"name"`
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // ... process request
}
```

---

### Issue #6: Manual JSON Construction & Missing Content-Type 🟡 **MEDIUM**
**Location:** Lines 82-83, 98-99, 132

**The Problem:**
```go
// Manual JSON string building
fmt.Fprintf(w, "{\"id\": %d, \"name\": \"%s\"}", user.ID, user.User_Name)

// Building JSON with string concatenation
var result = "["
for _, u := range data {
    userStr := fmt.Sprintf("{\"id\": %d, \"name\": \"%s\"},", u.ID, u.User_Name)
    result += userStr
}
result = result[:len(result)-1] + "]"  // Remove trailing comma
fmt.Fprintf(w, result)
```

**Why It's Broken:**
- **No proper JSON escaping** - if `User_Name` contains `"` or `\`, the JSON breaks
- **Potential injection vulnerability** - user input can break JSON structure
- No `Content-Type: application/json` header (except in one place)
- String concatenation in loop is inefficient (allocates repeatedly)
- Error-prone (missing commas, brackets, escaping)

**Impact:**
- ⚠️ **Invalid JSON responses** crash clients
- Potential XSS if user input contains special characters
- Poor performance (string concatenation in loop)
- Hard to maintain and extend

**How to Fix:**
```go
import "encoding/json"

func GetUser(w http.ResponseWriter, r *http.Request) {
    // ... fetch user ...
    
    // Use encoding/json - handles escaping automatically
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(user)  // Proper JSON encoding
}

func list_all_user(w http.ResponseWriter, r *http.Request) {
    m.RLock()
    users := make([]User, 0, len(data))
    for _, u := range data {
        users = append(users, u)
    }
    m.RUnlock()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)  // Clean and safe
}
```

---

### Issue #7: Ignored Error Handling 🟠 **LOW-MEDIUM**
**Location:** Line 78

**The Problem:**
```go
id, _ := strconv.Atoi(idQuery)  // What if conversion fails?
user, ok := data[id]  // 'id' could be 0 if conversion failed
```

**Why It's Broken:**
- Ignoring errors with `_` silently fails
- If `idQuery` is not a number, `id` will be `0`
- Returns wrong data (user with ID 0) or incorrect "not found"
- No way to distinguish between "ID 0 not found" and "invalid ID format"

**Impact:**
- Incorrect API behavior
- Confusing error messages
- Security issue (info disclosure)

**How to Fix:**
```go
id, err := strconv.Atoi(idQuery)
if err != nil {
    http.Error(w, "Invalid ID format", http.StatusBadRequest)
    return
}

user, ok := data[id]
if !ok {
    http.Error(w, "User not found", http.StatusNotFound)
    return
}
```

---

### Issue #8: Non-Idiomatic Naming & Global State 🟠 **LOW**
**Location:** Throughout file

**The Problem:**
```go
var data = make(map[int]User)      // Global mutable state
var m = &sync.RWMutex{}            // Global lock
var counter = 1                    // Global counter

type User struct {
    User_Name string  // Should be UserName (Go style)
    pass      string  // Unexported but used
}

func list_all_user(w http.ResponseWriter, r *http.Request)  // Should be camelCase or all exported
```

**Why It's Broken:**
- Global variables make testing impossible (shared state between tests)
- Can't run multiple instances or mock storage
- Naming doesn't follow Go conventions:
  - `User_Name` should be `UserName`
  - `list_all_user` should be `ListAllUsers` or `listAllUsers`
- Mixed exported/unexported fields (inconsistent)

**Impact:**
- Hard to test and maintain
- Doesn't follow Go idioms
- Looks unprofessional

**How to Fix:**
```go
// Encapsulate in a server struct
type Server struct {
    mu    sync.RWMutex
    users map[int]User
    nextID int
}

func NewServer() *Server {
    return &Server{
        users: make(map[int]User),
        nextID: 1,
    }
}

type User struct {
    ID       int    `json:"id"`
    UserName string `json:"user_name"`  // Proper naming + JSON tags
    Email    string `json:"email"`
    PasswordHash string `json:"-"`  // Never serialize passwords
}

func (s *Server) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
    // Method receiver, not global state
}
```

---

## Summary of Critical Fixes

| Priority | Issue | Fix |
|----------|-------|-----|
| 🔴 **P0** | Hardcoded secrets | Use environment variables |
| 🔴 **P0** | Plaintext passwords | Hash with bcrypt |
| 🔴 **P1** | Wrong lock type | Use `RLock()` for reads |
| 🟡 **P2** | Blocking sleep | Remove or use context |
| 🟡 **P2** | No method checks | Enforce POST for writes |
| 🟡 **P2** | Manual JSON | Use `encoding/json` |
| 🟠 **P3** | Ignored errors | Check and return errors |
| 🟠 **P3** | Global state & naming | Encapsulate in struct, follow Go style |

---

## How to Test for These Issues

```bash
# 1. Run with race detector
go run -race .

# 2. Check for hardcoded secrets
git grep -iE "password|secret|key|token" *.go

# 3. Run static analysis
go vet ./...

# 4. Use a linter
golangci-lint run

# 5. Load test for concurrency issues
# Use wrk, hey, or ab to send concurrent requests
```

---

## Next Steps

This code review demonstrates critical flaws that would fail any production code review. A complete fix would include:

1. ✅ Remove all hardcoded secrets and stop logging sensitive data
2. ✅ Implement bcrypt password hashing
3. ✅ Fix mutex usage (`RLock` for reads, `Lock` for writes)
4. ✅ Add HTTP method validation and proper status codes
5. ✅ Replace manual JSON with `encoding/json`
6. ✅ Encapsulate state in a `Server` struct
7. ✅ Add comprehensive error handling
8. ✅ Follow Go naming conventions
9. ✅ Write unit tests with table-driven tests
10. ✅ Add integration tests with `httptest`

---

**Assessment completed:** All critical security, concurrency, and design flaws have been identified and documented with fixes.
