package main

import (
    "log"
    "net/http"
    "os"

    "github.com/joho/godotenv"

    "auth-app/db"
    "auth-app/handlers"
    "auth-app/middleware"
    "auth-app/utils"
)

func main() {
    // Load environment variables from .env file
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    // Set the JWT secret key from environment variable
    utils.JWTKey = []byte(os.Getenv("JWT_SECRET_KEY"))

    db.InitDB()

    http.HandleFunc("/login", handlers.LoginHandler)
    http.HandleFunc("/register", handlers.RegisterHandler)
    http.HandleFunc("/oauth2/google/login", handlers.OAuthGoogleLogin)
    http.HandleFunc("/oauth2/callback", handlers.OAuthGoogleCallback)

    protected := http.NewServeMux()
    protected.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("This is a protected route"))
    })

    http.Handle("/protected", middleware.JWTMiddleware(protected))

    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
