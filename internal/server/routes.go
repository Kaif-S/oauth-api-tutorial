package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Add your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true, // Enable cookies/auth
	}))

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	r.GET("api/auth/callback/:provider", s.getAuthCallbackFunction)

	r.GET("/logout/:provider", s.handleLogout)

	r.GET("/auth/:provider", s.handleAuth)

	r.GET("/api/me", s.getCurrentuser)

	return r
}

func (s *Server) HelloWorldHandler(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.db.Health())
}

func (s *Server) handleLogout(c *gin.Context) {
	gothic.Logout(c.Writer, c.Request)
	c.Writer.Header().Set("Location", "/")
	c.Writer.WriteHeader(http.StatusTemporaryRedirect)
}

func (s *Server) handleAuth(c *gin.Context) {
	provider := c.Param("provider")

	q := c.Request.URL.Query()
	q.Set("provider", provider)
	c.Request.URL.RawQuery = q.Encode()

	ctx := context.WithValue(c.Request.Context(), "provider", provider)
	r := c.Request.WithContext(ctx)

	// DO NOT check CompleteUserAuth here. Just start the handshake cleanly.
	gothic.BeginAuthHandler(c.Writer, r)
}

func (s *Server) getAuthCallbackFunction(c *gin.Context) {

	provider := c.Param("provider")

	q := c.Request.URL.Query()
	q.Set("provider", provider)
	c.Request.URL.RawQuery = q.Encode()

	ctx := context.WithValue(c.Request.Context(), "provider", provider)
	r := c.Request.WithContext(ctx)

	user, err := gothic.CompleteUserAuth(c.Writer, r)
	if err != nil {
		fmt.Println("Auth callback error:", err)
		c.String(http.StatusBadRequest, "Authentication failed: %v", err)
		return
	}

	session, _ := gothic.Store.Get(r, "app-session")
	session.Values["userID"] = user.UserID
	session.Values["email"] = user.Email
	session.Values["name"] = user.FirstName
	session.Values["avatar"] = user.AvatarURL

	err = session.Save(r, c.Writer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Failed to save session"})
	}
	fmt.Println(user)
	// 302 StatusFound is preferred for cross-origin browser redirections
	c.Redirect(http.StatusFound, "http://localhost:5173/")
}

func (s *Server) getCurrentuser(c *gin.Context) {

	session, err := gothic.Store.Get(c.Request, "app-session")

	userID, exist := session.Values["userID"]
	if err != nil || !exist || userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": true, "message": "unauthorized: please log in"})
		c.Abort()
		return
	}

	c.Set("userID", userID)
	c.Set("email", session.Values["email"])
	c.Set("name", session.Values["name"])
	c.Set("avatar", session.Values["avatar"])

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user": gin.H{
			"id":        userID,
			"email":     session.Values["email"],
			"name":      session.Values["name"],
			"avatarurl": session.Values["avatar"],
		},
	})
}
