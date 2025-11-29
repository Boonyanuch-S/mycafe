package main

import (
    _ "week13-lab6/docs"
    "fmt"
    "os"
    "database/sql"
    _ "github.com/lib/pq"
    "log"
    "github.com/gin-gonic/gin"
    "net/http"
    "time"
    "strings"
    "encoding/json"
    swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
    "github.com/gin-contrib/cors"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

// ===================== Utility =====================
func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

var db *sql.DB
var jwtSecret = []byte("my-super-secret-key-change-in-production-2024")

// ===================== Error Response =====================
type ErrorResponse struct {
    Message string `json:"message"`
}

// ===================== USER / AUTH MODELS =====================
type User struct {
    ID           int       `json:"id"`
    Username     string    `json:"username"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    IsActive     bool      `json:"is_active"`
    CreatedAt    time.Time `json:"created_at"`
}

type LoginRequest struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
    AccessToken  string   `json:"access_token"`
    RefreshToken string   `json:"refresh_token"`
    User         UserInfo `json:"user"`
}

type UserInfo struct {
    ID       int      `json:"id"`
    Username string   `json:"username"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
}

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`
}

type CustomClaims struct {
    UserID   int      `json:"user_id"`
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
    jwt.RegisteredClaims
}

// ===================== Cafe Models =====================
type Drink struct {
    ID          int       `json:"id"`
    SubCategory string    `json:"sub_category"`
    Name        string    `json:"name"`
    DrinkType   string    `json:"drink_type"`
    Price       float64   `json:"price"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

type Food struct {
    ID          int       `json:"id"`
    SubCategory string    `json:"sub_category"`
    Name        string    `json:"name"`
    Price       float64   `json:"price"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

type Dessert struct {
    ID          int       `json:"id"`
    SubCategory string    `json:"sub_category"`
    Name        string    `json:"name"`
    Price       float64   `json:"price"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// ===================== Password =====================
func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

func verifyPassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// ===================== JWT =====================
func generateAccessToken(userID int, username string, roles []string) (string, error) {
    expires := time.Now().Add(15 * time.Minute)

    claims := &CustomClaims{
        UserID:   userID,
        Username: username,
        Roles:    roles,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expires),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "cafe-api",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

func generateRefreshToken(userID int, username string) (string, error) {
    expires := time.Now().Add(7 * 24 * time.Hour)

    claims := &CustomClaims{
        UserID:   userID,
        Username: username,
        Roles:    []string{},
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expires),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "cafe-api",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

func verifyToken(tokenStr string) (*CustomClaims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method")
        }
        return jwtSecret, nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
        return claims, nil
    }

    return nil, fmt.Errorf("invalid token")
}

// ===================== Database Helpers =====================
func getUserRoles(userID int) ([]string, error) {
    rows, err := db.Query(`
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1
    `, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var roles []string
    for rows.Next() {
        var role string
        rows.Scan(&role)
        roles = append(roles, role)
    }
    return roles, nil
}

func checkUserPermission(userID int, permission string) bool {
    var count int
    err := db.QueryRow(`
        SELECT COUNT(*)
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = $1 AND p.name = $2
    `, userID, permission).Scan(&count)

    if err != nil {
        log.Println("permission error:", err)
        return false
    }

    return count > 0
}

func storeRefreshToken(userID int, token string, expiresAt time.Time) error {
    _, err := db.Exec(`
        INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
    `, userID, token, expiresAt)
    return err
}

func revokeRefreshToken(token string) error {
    _, err := db.Exec(`
        UPDATE refresh_tokens SET revoked_at = NOW()
        WHERE token = $1 AND revoked_at IS NULL
    `, token)
    return err
}

func isRefreshTokenValid(token string) (int, bool) {
    var userID int
    err := db.QueryRow(`
        SELECT user_id
        FROM refresh_tokens
        WHERE token = $1 AND revoked_at IS NULL AND expires_at > NOW()
    `, token).Scan(&userID)

    if err != nil {
        return 0, false
    }
    return userID, true
}

func logAudit(userID int, action, resource string, resourceID interface{}, details map[string]interface{}, c *gin.Context) {
    dJSON, _ := json.Marshal(details)
    rid := ""
    if resourceID != nil {
        rid = fmt.Sprintf("%v", resourceID)
    }

    db.Exec(`
        INSERT INTO audit_logs (user_id, action, resource, resource_id, details, ip_address, user_agent)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
    `,
        userID,
        action,
        resource,
        rid,
        dJSON,
        c.ClientIP(),
        c.GetHeader("User-Agent"),
    )
}

// ===================== Init DB =====================
func initDB() {
    host := getEnv("DB_HOST", "")
    name := getEnv("DB_NAME", "")
    user := getEnv("DB_USER", "")
    password := getEnv("DB_PASSWORD", "")
    port := getEnv("DB_PORT", "")

    conn := fmt.Sprintf(
        "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
        host, port, user, password, name,
    )

    var err error
    db, err = sql.Open("postgres", conn)
    if err != nil {
        log.Fatal("failed to open db:", err)
    }

    db.SetMaxOpenConns(20)
    db.SetMaxIdleConns(20)
    db.SetConnMaxLifetime(5 * time.Minute)

    if err := db.Ping(); err != nil {
        log.Fatal("failed to connect db:", err)
    }

    log.Println("database connected")
}

// ===================== AUTH HANDLERS =====================
func login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    var user User
    err := db.QueryRow(`
        SELECT id, username, email, password_hash, is_active
        FROM users WHERE username = $1
    `, req.Username).Scan(
        &user.ID,
        &user.Username,
        &user.Email,
        &user.PasswordHash,
        &user.IsActive,
    )

    if err == sql.ErrNoRows {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
        return
    }

    if !user.IsActive {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "account disabled"})
        return
    }

    if verifyPassword(user.PasswordHash, req.Password) != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }

    roles, _ := getUserRoles(user.ID)

    access, _ := generateAccessToken(user.ID, user.Username, roles)
    refresh, _ := generateRefreshToken(user.ID, user.Username)

    storeRefreshToken(user.ID, refresh, time.Now().Add(7*24*time.Hour))

    db.Exec("UPDATE users SET last_login = NOW() WHERE id = $1", user.ID)

    logAudit(user.ID, "login", "auth", nil, gin.H{"username": user.Username}, c)

    c.JSON(http.StatusOK, LoginResponse{
        AccessToken:  access,
        RefreshToken: refresh,
        User: UserInfo{
            ID:       user.ID,
            Username: user.Username,
            Email:    user.Email,
            Roles:    roles,
        },
    })
}

func refreshTokenHandler(c *gin.Context) {
    var req RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    userID, ok := isRefreshTokenValid(req.RefreshToken)
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
        return
    }

    var username string
    db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&username)

    roles, _ := getUserRoles(userID)

    access, _ := generateAccessToken(userID, username, roles)

    c.JSON(http.StatusOK, gin.H{"access_token": access})
}

func logout(c *gin.Context) {
    var req RefreshRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    revokeRefreshToken(req.RefreshToken)

    if uid, exists := c.Get("user_id"); exists {
        logAudit(uid.(int), "logout", "auth", nil, nil, c)
    }

    c.JSON(http.StatusOK, gin.H{"message": "logout success"})
}

// ===================== MIDDLEWARE =====================
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        auth := c.GetHeader("Authorization")
        if auth == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "missing auth header"})
            c.Abort()
            return
        }

        parts := strings.Split(auth, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth format"})
            c.Abort()
            return
        }

        claims, err := verifyToken(parts[1])
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
            c.Abort()
            return
        }

        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("roles", claims.Roles)

        c.Next()
    }
}

func requirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        uid, exists := c.Get("user_id")
        if !exists || !checkUserPermission(uid.(int), permission) {
            c.JSON(http.StatusForbidden, gin.H{
                "error":    "insufficient permission",
                "required": permission,
            })
            c.Abort()
            return
        }
        c.Next()
    }
}

// ===================== DRINKS =====================
func getAllDrinks(c *gin.Context) {
    rows, err := db.Query(`
        SELECT id, sub_category, name, drink_type, price, description, created_at, updated_at 
        FROM drinks`)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer rows.Close()

    var list []Drink
    for rows.Next() {
        var d Drink
        rows.Scan(&d.ID, &d.SubCategory, &d.Name, &d.DrinkType, &d.Price, &d.Description, &d.CreatedAt, &d.UpdatedAt)
        list = append(list, d)
    }
    c.JSON(http.StatusOK, list)
}

func createDrink(c *gin.Context) {
    var d Drink
    if err := c.ShouldBindJSON(&d); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err := db.QueryRow(`
        INSERT INTO drinks (sub_category,name,drink_type,price,description)
        VALUES ($1,$2,$3,$4,$5)
        RETURNING id,created_at,updated_at
    `, d.SubCategory, d.Name, d.DrinkType, d.Price, d.Description).
        Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    uid := c.GetInt("user_id")
    logAudit(uid, "create", "drinks", d.ID, gin.H{"name": d.Name}, c)

    c.JSON(http.StatusCreated, d)
}

// ===================== FOODS =====================
func getAllFoods(c *gin.Context) {
    rows, err := db.Query(`
        SELECT id, sub_category, name, price, description, created_at, updated_at 
        FROM foods`)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer rows.Close()

    var list []Food
    for rows.Next() {
        var f Food
        rows.Scan(&f.ID, &f.SubCategory, &f.Name, &f.Price, &f.Description, &f.CreatedAt, &f.UpdatedAt)
        list = append(list, f)
    }
    c.JSON(http.StatusOK, list)
}

func createFood(c *gin.Context) {
    var f Food
    if err := c.ShouldBindJSON(&f); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err := db.QueryRow(`
        INSERT INTO foods (sub_category,name,price,description)
        VALUES ($1,$2,$3,$4)
        RETURNING id,created_at,updated_at
    `, f.SubCategory, f.Name, f.Price, f.Description).
        Scan(&f.ID, &f.CreatedAt, &f.UpdatedAt)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    uid := c.GetInt("user_id")
    logAudit(uid, "create", "foods", f.ID, gin.H{"name": f.Name}, c)

    c.JSON(http.StatusCreated, f)
}

// ===================== DESSERTS =====================
func getAllDesserts(c *gin.Context) {
    rows, err := db.Query(`
        SELECT id, sub_category, name, price, description, created_at, updated_at 
        FROM desserts`)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer rows.Close()

    var list []Dessert
    for rows.Next() {
        var d Dessert
        rows.Scan(&d.ID, &d.SubCategory, &d.Name, &d.Price, &d.Description, &d.CreatedAt, &d.UpdatedAt)
        list = append(list, d)
    }

    c.JSON(http.StatusOK, list)
}

func createDessert(c *gin.Context) {
    var d Dessert
    if err := c.ShouldBindJSON(&d); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err := db.QueryRow(`
        INSERT INTO desserts (sub_category,name,price,description)
        VALUES ($1,$2,$3,$4)
        RETURNING id,created_at,updated_at
    `, d.SubCategory, d.Name, d.Price, d.Description).
        Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    uid := c.GetInt("user_id")
    logAudit(uid, "create", "desserts", d.ID, gin.H{"name": d.Name}, c)

    c.JSON(http.StatusCreated, d)
}

// ===================== Swagger Info =====================
// @title           Cafe API with Authentication
// @version         1.0
// @description     Cafe Menu API with JWT Authentication and RBAC
// @host            localhost:8080
// @BasePath        /api/v1

// ===================== MAIN =====================
func main() {
    initDB()
    defer db.Close()

    r := gin.Default()
    r.Use(cors.Default())

    // Swagger
    r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

    // Health Check
    r.GET("/health", func(c *gin.Context) {
        if err := db.Ping(); err != nil {
            c.JSON(http.StatusServiceUnavailable, gin.H{"message": "unhealthy"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"message": "healthy"})
    })

    // AUTH
    auth := r.Group("/auth")
    {
        auth.POST("/login", login)
        auth.POST("/refresh", refreshTokenHandler)
        auth.POST("/logout", logout)
    }

    // API Protected
    api := r.Group("/api/v1")
    api.Use(authMiddleware())
    {
        // Drinks
        api.GET("/drinks", requirePermission("drinks:read"), getAllDrinks)
        api.POST("/drinks", requirePermission("drinks:create"), createDrink)

        // Foods
        api.GET("/foods", requirePermission("foods:read"), getAllFoods)
        api.POST("/foods", requirePermission("foods:create"), createFood)

        // Desserts
        api.GET("/desserts", requirePermission("desserts:read"), getAllDesserts)
        api.POST("/desserts", requirePermission("desserts:create"), createDessert)
    }

    r.Run(":8080")
}
