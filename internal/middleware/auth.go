package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ndyabagye/auth-service/internal/utils"
	"github.com/sirupsen/logrus"
)

func AuthMiddleware(jwtSecret string, logger *logrus.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            logger.Warn("Missing authorization header")
            utils.SendError(c, http.StatusUnauthorized, "Authorization header required", nil)
            c.Abort()
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            logger.Warn("Invalid authorization header format")
            utils.SendError(c, http.StatusUnauthorized, "Invalid authorization header format", nil)
            c.Abort()
            return
        }

        token := parts[1]
        claims, err := utils.ValidateToken(token, jwtSecret)
        if err != nil {
            logger.WithError(err).Warn("Invalid token")
            utils.SendError(c, http.StatusUnauthorized, "Invalid or expired token", err)
            c.Abort()
            return
        }

        c.Set("user_id", claims.UserID)
        c.Set("email", claims.Email)
        c.Next()
    }
}

func GetUserID(c *gin.Context) (uuid.UUID, bool) {
    userID, exists := c.Get("user_id")
    if !exists {
        return uuid.Nil, false
    }
    id, ok := userID.(uuid.UUID)
    return id, ok
}