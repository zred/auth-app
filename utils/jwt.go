package utils

import (
    "time"

    "github.com/dgrijalva/jwt-go"
    "os"
)

var JWTKey []byte

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

func init() {
    JWTKey = []byte(os.Getenv("JWT_SECRET_KEY"))
}

func GenerateJWT(username string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(JWTKey)
    if err != nil {
        return "", err
    }

    return tokenString, nil
}

func VerifyJWT(tokenString string) (*Claims, error) {
    claims := &Claims{}

    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return JWTKey, nil
    })

    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            return nil, err
        }
        return nil, err
    }

    if !token.Valid {
        return nil, err
    }

    return claims, nil
}
