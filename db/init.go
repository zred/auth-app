package db

import (
    "log"

    "auth-app/models"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
    var err error
    DB, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    DB.AutoMigrate(&models.User{})
}
