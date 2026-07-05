package auth

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

const (
	key    = "u1jdWRuZ2czkYshM9I15Z/GBS7pr9f+ND7OGITFhgLQ="
	MaxAge = 86400 * 30
	IsProd = false
)

func NewAuth() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error while handling .env file")
	}

	googleClientSECRET := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")

	store := sessions.NewCookieStore([]byte(key))

	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = IsProd
	store.Options.SameSite = http.SameSiteLaxMode

	gothic.Store = store

	goth.UseProviders(
		google.New(googleClientID, googleClientSECRET, "http://localhost:3000/api/auth/callback/google"),
	)
}
