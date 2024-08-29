package middleware

import (
	"go-template/internal/auth/domain/cookiesession"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CookieSessionAuthMiddleware(cookieSessionService *cookiesession.CookieSessionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. check if user is authenticated
		// 2. if user is authenticated, set user info in the context
		// 3. if user is not authenticated, return unauthorized
		// authenticate user
		sessionId, err := c.Cookie("session_id")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		authUserInfo, err := cookieSessionService.Authenticate(c, sessionId)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Set("user_info", authUserInfo)
		c.Next()
	}
}
