package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ndyabagye/auth-service/internal/middleware"
	"github.com/ndyabagye/auth-service/internal/models"
	"github.com/ndyabagye/auth-service/internal/services"
	"github.com/ndyabagye/auth-service/internal/utils"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
    service *services.AuthService
    logger  *logrus.Logger
}

func NewAuthHandler(service *services.AuthService, logger *logrus.Logger) *AuthHandler {
    return &AuthHandler{
        service: service,
        logger:  logger,
    }
}

func (h *AuthHandler) Signup(c *gin.Context) {
    var req models.SignupRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.logger.WithError(err).Warn("Invalid request body")
        utils.SendError(c, http.StatusBadRequest, "Invalid request body", err)
        return
    }

    resp, err := h.service.Signup(&req)
    if err != nil {
        if err == services.ErrUserExists {
            utils.SendError(c, http.StatusConflict, "User already exists", err)
            return
        }
        utils.SendError(c, http.StatusInternalServerError, "Failed to register user", err)
        return
    }

    utils.SendSuccess(c, http.StatusCreated, "User registered successfully", resp)
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req models.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.logger.WithError(err).Warn("Invalid request body")
        utils.SendError(c, http.StatusBadRequest, "Invalid request body", err)
        return
    }

    deviceInfo := c.GetHeader("User-Agent")
    resp, err := h.service.Login(&req, deviceInfo)
    if err != nil {
        if err == services.ErrInvalidCreds {
            utils.SendError(c, http.StatusUnauthorized, "Invalid credentials", err)
            return
        }
        utils.SendError(c, http.StatusInternalServerError, "Login failed", err)
        return
    }

    utils.SendSuccess(c, http.StatusOK, "Login successful", resp)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
    var req models.RefreshTokenRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.logger.WithError(err).Warn("Invalid request body")
        utils.SendError(c, http.StatusBadRequest, "Invalid request body", err)
        return
    }

    resp, err := h.service.RefreshToken(req.RefreshToken)
    if err != nil {
        if err == services.ErrInvalidToken {
            utils.SendError(c, http.StatusUnauthorized, "Invalid or expired refresh token", err)
            return
        }
        utils.SendError(c, http.StatusInternalServerError, "Token refresh failed", err)
        return
    }

    utils.SendSuccess(c, http.StatusOK, "Token refreshed successfully", resp)
}

func (h *AuthHandler) Logout(c *gin.Context) {
    var req models.RefreshTokenRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.logger.WithError(err).Warn("Invalid request body")
        utils.SendError(c, http.StatusBadRequest, "Invalid request body", err)
        return
    }

    if err := h.service.Logout(req.RefreshToken); err != nil {
        utils.SendError(c, http.StatusInternalServerError, "Logout failed", err)
        return
    }

    utils.SendSuccess(c, http.StatusOK, "Logout successful", nil)
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
    userID, ok := middleware.GetUserID(c)
    if !ok {
        utils.SendError(c, http.StatusUnauthorized, "User not authenticated", nil)
        return
    }

    h.logger.WithField("user_id", userID).Info("Fetching user profile")
    utils.SendSuccess(c, http.StatusOK, "Profile retrieved", gin.H{
        "user_id": userID,
        "email":   c.GetString("email"),
    })
}