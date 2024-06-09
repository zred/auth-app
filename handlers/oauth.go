package handlers

import (
    "context"
    "encoding/json"
    "net/http"
    "os"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

var googleOauthConfig = &oauth2.Config{
    RedirectURL:  "http://localhost:8080/oauth2/callback",
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
    Endpoint:     google.Endpoint,
}

var oauthStateString = "random"

func OAuthGoogleLogin(w http.ResponseWriter, r *http.Request) {
    url := googleOauthConfig.AuthCodeURL(oauthStateString)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func OAuthGoogleCallback(w http.ResponseWriter, r *http.Request) {
    if r.FormValue("state") != oauthStateString {
        http.Error(w, "Invalid state", http.StatusUnauthorized)
        return
    }

    token, err := googleOauthConfig.Exchange(context.Background(), r.FormValue("code"))
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusUnauthorized)
        return
    }

    response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
    if err != nil {
        http.Error(w, "Failed to get user info", http.StatusUnauthorized)
        return
    }
    defer response.Body.Close()

    var userInfo struct {
        Email string `json:"email"`
    }
    if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
        http.Error(w, "Failed to decode user info", http.StatusUnauthorized)
        return
    }

    // Here you would typically check if the user exists in your DB and create a session or JWT
    // For simplicity, we will just return the email
    w.Write([]byte("User Info: " + userInfo.Email))
}
