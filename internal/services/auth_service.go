package services

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ndyabagye/auth-service/internal/config"
	"github.com/ndyabagye/auth-service/internal/models"
	"github.com/ndyabagye/auth-service/internal/repository"
	"github.com/ndyabagye/auth-service/internal/utils"
	"github.com/sirupsen/logrus"
)

var (
    ErrUserExists      = errors.New("user already exists")
    ErrInvalidCreds    = errors.New("invalid credentials")
    ErrInvalidToken    = errors.New("invalid or expired token")
)

type AuthService struct {
    repo   *repository.UserRepository
    config *config.Config
    logger *logrus.Logger
}

func NewAuthService(repo *repository.UserRepository, cfg *config.Config, logger *logrus.Logger) *AuthService {
    return &AuthService{
        repo:   repo,
        config: cfg,
        logger: logger,
    }
}

func (s *AuthService) Signup(req *models.SignupRequest) (*models.AuthResponse, error) {
    s.logger.WithFields(logrus.Fields{
        "email": req.Email,
        "name":  req.Name,
    }).Info("Processing signup request")

    // Check if user exists
    existingUser, err := s.repo.FindByEmail(req.Email)
    if err != nil {
        s.logger.WithError(err).Error("Failed to check existing user")
        return nil, err
    }
    if existingUser != nil {
        s.logger.Warn("User already exists")
        return nil, ErrUserExists
    }

    // Hash password
    hashedPassword, err := utils.HashPassword(req.Password, s.config.Security.BcryptCost)
    if err != nil {
        s.logger.WithError(err).Error("Failed to hash password")
        return nil, err
    }

    // Create user
    user := &models.User{
        Email:        req.Email,
        PasswordHash: hashedPassword,
        Name:         req.Name,
        IsVerified:   false,
    }

    if err := s.repo.Create(user); err != nil {
        s.logger.WithError(err).Error("Failed to create user")
        return nil, err
    }

    s.logger.WithField("user_id", user.ID).Info("User created successfully")

    // Generate tokens
    accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, s.config.JWT.Secret, s.config.JWT.Expiry)
    if err != nil {
        s.logger.WithError(err).Error("Failed to generate access token")
        return nil, err
    }

    refreshToken := utils.GenerateRefreshToken()
    if err := s.storeRefreshToken(user.ID, refreshToken, ""); err != nil {
        s.logger.WithError(err).Error("Failed to store refresh token")
        return nil, err
    }

    return &models.AuthResponse{
        Success:      true,
        Message:      "User registered successfully",
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        User:         user,
    }, nil
}

func (s *AuthService) Login(req *models.LoginRequest, deviceInfo string) (*models.AuthResponse, error) {
    s.logger.WithField("email", req.Email).Info("Processing login request")

    // Find user
    user, err := s.repo.FindByEmail(req.Email)
    if err != nil {
        s.logger.WithError(err).Error("Failed to find user")
        return nil, err
    }
    if user == nil {
        s.logger.Warn("User not found")
        return nil, ErrInvalidCreds
    }

    // Compare password
    if err := utils.ComparePassword(user.PasswordHash, req.Password); err != nil {
        s.logger.Warn("Invalid password")
        return nil, ErrInvalidCreds
    }

    s.logger.WithField("user_id", user.ID).Info("User authenticated successfully")

    // Generate tokens
    accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, s.config.JWT.Secret, s.config.JWT.Expiry)
    if err != nil {
        s.logger.WithError(err).Error("Failed to generate access token")
        return nil, err
    }

    refreshToken := utils.GenerateRefreshToken()
    if err := s.storeRefreshToken(user.ID, refreshToken, deviceInfo); err != nil {
        s.logger.WithError(err).Error("Failed to store refresh token")
        return nil, err
    }

    return &models.AuthResponse{
        Success:      true,
        Message:      "Login successful",
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        User:         user,
    }, nil
}

func (s *AuthService) RefreshToken(refreshTokenStr string) (*models.AuthResponse, error) {
    s.logger.Info("Processing refresh token request")

    // Find refresh token
    rt, err := s.repo.FindRefreshToken(refreshTokenStr)
    if err != nil {
        s.logger.WithError(err).Error("Failed to find refresh token")
        return nil, err
    }
    if rt == nil || rt.Revoked {
        s.logger.Warn("Invalid or revoked refresh token")
        return nil, ErrInvalidToken
    }

    // Check expiration
    if time.Now().After(rt.ExpiresAt) {
        s.logger.Warn("Refresh token expired")
        return nil, ErrInvalidToken
    }

    // Find user
    user, err := s.repo.FindByID(rt.UserID)
    if err != nil {
        s.logger.WithError(err).Error("Failed to find user")
        return nil, err
    }
    if user == nil {
        s.logger.Warn("User not found")
        return nil, ErrInvalidToken
    }

    // Revoke old token
    if err := s.repo.RevokeRefreshToken(refreshTokenStr); err != nil {
        s.logger.WithError(err).Error("Failed to revoke old token")
        return nil, err
    }

    s.logger.WithField("user_id", user.ID).Info("Token refreshed successfully")

    // Generate new tokens
    accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, s.config.JWT.Secret, s.config.JWT.Expiry)
    if err != nil {
        s.logger.WithError(err).Error("Failed to generate access token")
        return nil, err
    }

    newRefreshToken := utils.GenerateRefreshToken()
    if err := s.storeRefreshToken(user.ID, newRefreshToken, rt.DeviceInfo); err != nil {
        s.logger.WithError(err).Error("Failed to store new refresh token")
        return nil, err
    }

    return &models.AuthResponse{
        Success:      true,
        Message:      "Token refreshed successfully",
        AccessToken:  accessToken,
        RefreshToken: newRefreshToken,
        User:         user,
    }, nil
}

func (s *AuthService) Logout(refreshTokenStr string) error {
    s.logger.Info("Processing logout request")

    if err := s.repo.RevokeRefreshToken(refreshTokenStr); err != nil {
        s.logger.WithError(err).Error("Failed to revoke token")
        return err
    }

    s.logger.Info("Logout successful")
    return nil
}

func (s *AuthService) storeRefreshToken(userID uuid.UUID, token, deviceInfo string) error {
    rt := &models.RefreshToken{
        UserID:     userID,
        Token:      token,
        ExpiresAt:  time.Now().Add(s.config.JWT.RefreshTokenExpiry),
        DeviceInfo: deviceInfo,
    }
    return s.repo.StoreRefreshToken(rt)
}
