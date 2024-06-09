package main

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
)

type ClientSecret struct {
    Web struct {
        ClientID     string   `json:"client_id"`
        ClientSecret string   `json:"client_secret"`
        RedirectURIs []string `json:"redirect_uris"`
    } `json:"web"`
}

func deriveJWTSecret(clientID, clientSecret string) string {
    data := clientID + clientSecret
    hash := sha256.New()
    hash.Write([]byte(data))
    return hex.EncodeToString(hash.Sum(nil))
}

func main() {
    // Open the client_secret.json file
    file, err := os.Open("client_secret.json")
    if err != nil {
        log.Fatalf("Failed to open client_secret.json: %v", err)
    }
    defer file.Close()

    // Read the content of the file
    byteValue, err := ioutil.ReadAll(file)
    if err != nil {
        log.Fatalf("Failed to read client_secret.json: %v", err)
    }

    // Unmarshal the JSON content into the struct
    var clientSecret ClientSecret
    if err := json.Unmarshal(byteValue, &clientSecret); err != nil {
        log.Fatalf("Failed to unmarshal JSON: %v", err)
    }

    // Derive the JWT secret using the client_id and client_secret
    jwtSecret := deriveJWTSecret(clientSecret.Web.ClientID, clientSecret.Web.ClientSecret)

    // Create or update the .env file
    envFile, err := os.OpenFile(".env", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
    if err != nil {
        log.Fatalf("Failed to open .env file: %v", err)
    }
    defer envFile.Close()

    // Write the client_id, client_secret, and derived JWT secret to the .env file
    _, err = envFile.WriteString(fmt.Sprintf("GOOGLE_CLIENT_ID=%s\n", clientSecret.Web.ClientID))
    if err != nil {
        log.Fatalf("Failed to write to .env file: %v", err)
    }

    _, err = envFile.WriteString(fmt.Sprintf("GOOGLE_CLIENT_SECRET=%s\n", clientSecret.Web.ClientSecret))
    if err != nil {
        log.Fatalf("Failed to write to .env file: %v", err)
    }

    _, err = envFile.WriteString(fmt.Sprintf("JWT_SECRET_KEY=%s\n", jwtSecret))
    if err != nil {
        log.Fatalf("Failed to write to .env file: %v", err)
    }

    fmt.Println(".env file has been created/updated successfully.")
}
