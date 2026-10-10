package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

type AuthHandler struct {
    DB        *pgxpool.Pool
    JWTSecret []byte
}

type AuthRequest struct {
    Name     string `json:"name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type User struct {
    ID    int64  `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}
func hashPassword(password string) (string, error) {
    salt := make([]byte, 16)

    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    hash := argon2.IDKey(
        []byte(password),
        salt,
        2,       // iterations
        64*1024, // memory in KiB: 64 MiB
        1,       // parallelism
        32,      // output length
    )

    encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
    encodedHash := base64.RawStdEncoding.EncodeToString(hash)

    return encodedSalt + ":" + encodedHash, nil
}

func checkPassword(password, storedHash string) bool {
    parts := strings.Split(storedHash, ":")
    if len(parts) != 2 {
        return false
    }

    salt, err := base64.RawStdEncoding.DecodeString(parts[0])
    if err != nil || len(salt) != 16 {
        return false
    }

    expectedHash, err := base64.RawStdEncoding.DecodeString(parts[1])
    if err != nil || len(expectedHash) != 32 {
        return false
    }

    actualHash := argon2.IDKey(
        []byte(password),
        salt,
        2,
        64*1024,
        1,
        32,
    )

    return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
func (h *AuthHandler) Register(c *gin.Context) {
    var req AuthRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid request body",
        })
        return
    }

    req.Name = strings.TrimSpace(req.Name)
    req.Email = strings.ToLower(strings.TrimSpace(req.Email))

    if req.Name == "" ||
        len(req.Name) > 100 ||
        len(req.Email) == 0 ||
        len(req.Email) > 255 ||
        !strings.Contains(req.Email, "@") ||
        len(req.Password) < 8 ||
        len(req.Password) > 1024 {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid name, email, or password",
        })
        return
    }

    passwordHash, err := hashPassword(req.Password)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Could not process password",
        })
        return
    }

    var user User

    err = h.DB.QueryRow(
        c.Request.Context(),
        `INSERT INTO users (name, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, name, email`,
        req.Name,
        req.Email,
        passwordHash,
    ).Scan(&user.ID, &user.Name, &user.Email)

    if err != nil {
        if strings.Contains(err.Error(), "23505") {
            c.JSON(http.StatusConflict, gin.H{
                "error": "Email is already registered",
            })
            return
        }

        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Could not create account",
        })
        return
    }

    c.JSON(http.StatusCreated, gin.H{
        "message": "Registration successful",
        "user":    user,
    })
}
func (h *AuthHandler) Login(c *gin.Context) {
    var req AuthRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid request body",
        })
        return
    }

    email := strings.ToLower(strings.TrimSpace(req.Email))

    var user User
    var storedHash string

    err := h.DB.QueryRow(
        c.Request.Context(),
        `SELECT id, name, email, password_hash
         FROM users
         WHERE email = $1`,
        email,
    ).Scan(
        &user.ID,
        &user.Name,
        &user.Email,
        &storedHash,
    )

    if err != nil {
        if err == pgx.ErrNoRows {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid email or password",
            })
            return
        }

        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Login failed",
        })
        return
    }

    if !checkPassword(req.Password, storedHash) {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Invalid email or password",
        })
        return
    }

    claims := jwt.RegisteredClaims{
        Subject:   strings.TrimSpace(string(rune(user.ID))),
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    signedToken, err := token.SignedString(h.JWTSecret)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Could not create access token",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message":      "Login successful",
        "access_token": signedToken,
        "token_type":   "Bearer",
        "expires_in":   900,
        "user":         user,
    })
}
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        parts := strings.SplitN(authHeader, " ", 2)

        if len(parts) != 2 ||
            !strings.EqualFold(parts[0], "Bearer") ||
            parts[1] == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": "Missing or invalid authorization header",
            })
            return
        }

        claims := &jwt.RegisteredClaims{}

        token, err := jwt.ParseWithClaims(
            parts[1],
            claims,
            func(token *jwt.Token) (interface{}, error) {
                if token.Method != jwt.SigningMethodHS256 {
                    return nil, jwt.ErrSignatureInvalid
                }
                return h.JWTSecret, nil
            },
            jwt.WithValidMethods([]string{"HS256"}),
        )

        if err != nil || !token.Valid || claims.Subject == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid or expired token",
            })
            return
        }

        c.Set("user_id", claims.Subject)
        c.Next()
    }
}