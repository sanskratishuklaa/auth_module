package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

func main() {
	
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using environment variables")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) < 32 {
		log.Fatal("JWT_SECRET must contain at least 32 bytes")
	}
	db := connectDB()
	defer db.Close()

	auth := &AuthHandler{
		DB:        db,
		JWTSecret: []byte(jwtSecret),
	}

	
	router := gin.Default()


	router.POST("/register", auth.Register)
	router.POST("/login", auth.Login)

	
	protected := router.Group("/api")
	protected.Use(auth.AuthMiddleware())
	protected.GET("/profile", func(c *gin.Context) {
		userIDValue, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User ID not found",
			})
			return
		}

		userID, ok := userIDValue.(int64)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID",
			})
			return
		}

		var user User

		err := db.QueryRow(
			c.Request.Context(),
			`SELECT id, name, email
			 FROM users
			 WHERE id = $1`,
			userID,
		).Scan(
			&user.ID,
			&user.Name,
			&user.Email,
		)

		if err != nil {
			if err == pgx.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "User not found",
				})
				return
			}

			log.Printf("Failed to fetch user profile: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Could not fetch user profile",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Profile fetched successfully",
			"user":    user,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Server starting on port", port)

	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}