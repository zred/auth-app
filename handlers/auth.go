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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        email := r.FormValue("email")
        password := r.FormValue("password")

        hashedPassword, err := utils.HashPassword(password)
        if err != nil {
            http.Error(w, "Failed to hash password", http.StatusInternalServerError)
            return
        }

        user := models.User{Username: username, Email: email, Password: hashedPassword}
        if err := db.DB.Create(&user).Error; err != nil {
            if r.Header.Get("HX-Request") != "" {
                tmpl, _ := template.New("error").Parse(`<p class="text-red-500">Failed to register user</p>`)
                tmpl.Execute(w, nil)
                return
            }
            http.Error(w, "Failed to register user", http.StatusInternalServerError)
            return
        }

        log.Println("Registration successful:", email)
        if r.Header.Get("HX-Request") != "" {
            tmpl, _ := template.New("success").Parse(`<p class="text-green-500">Registration successful!</p>`)
            tmpl.Execute(w, nil)
            return
        }
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    tmpl, err := template.ParseFiles("templates/register.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}