package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func connectDB() *pgxpool.Pool {
    databaseURL := os.Getenv("DATABASE_URL")

    db, err := pgxpool.New(context.Background(), databaseURL)
    if err != nil {
        log.Fatal("Unable to configure database:", err)
    }

    ctx, cancel := context.WithTimeout(
        context.Background(),
        5*time.Second,
    )
    defer cancel()

    if err := db.Ping(ctx); err != nil {
        db.Close()
        log.Fatal("Unable to connect to PostgreSQL:", err)
    }

    log.Println("PostgreSQL connected successfully")
    return db
}