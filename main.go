package main

import (
    "log"
    "net/http"

    "auth-app/db"
    "auth-app/handlers"
)

func main() {
    db.InitDB()

    http.HandleFunc("/login", handlers.LoginHandler)
    http.HandleFunc("/register", handlers.RegisterHandler)

    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
