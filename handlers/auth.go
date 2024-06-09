package handlers

import (
    "html/template"
    "log"
    "net/http"
    "time"

    "auth-app/db"
    "auth-app/models"
    "auth-app/utils"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        email := r.FormValue("email")
        password := r.FormValue("password")

        var user models.User
        if err := db.DB.Where("email = ?", email).First(&user).Error; err != nil {
            if r.Header.Get("HX-Request") != "" {
                tmpl, _ := template.New("error").Parse(`<p class="text-red-500">Invalid email or password</p>`)
                tmpl.Execute(w, nil)
                return
            }
            tmpl, _ := template.New("error").Parse(`<p class="text-red-500">Invalid email or password</p>`)
            tmpl.Execute(w, nil)
            return
        }

        if !utils.CheckPasswordHash(password, user.Password) {
            if r.Header.Get("HX-Request") != "" {
                tmpl, _ := template.New("error").Parse(`<p class="text-red-500">Invalid email or password</p>`)
                tmpl.Execute(w, nil)
                return
            }
            tmpl, _ := template.New("error").Parse(`<p class="text-red-500">Invalid email or password</p>`)
            tmpl.Execute(w, nil)
            return
        }

        log.Println("Login successful:", email)
        token, err := utils.GenerateJWT(user.Username)
        if err != nil {
            http.Error(w, "Failed to generate token", http.StatusInternalServerError)
            return
        }

        http.SetCookie(w, &http.Cookie{
            Name:     "token",
            Value:    token,
            Expires:  time.Now().Add(24 * time.Hour),
            HttpOnly: true,
        })

        if r.Header.Get("HX-Request") != "" {
            tmpl, _ := template.New("success").Parse(`<p class="text-green-500">Login successful!</p>`)
            tmpl.Execute(w, nil)
            return
        }
        tmpl, err := template.ParseFiles("templates/login.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
        return
    }
    tmpl, err := template.ParseFiles("templates/login.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}
