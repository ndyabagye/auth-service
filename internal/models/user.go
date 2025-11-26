package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct{
	ID           uuid.UUID `json:"id"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    Name         string    `json:"name"`
    IsVerified   bool      `json:"is_verified"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type RefreshToken struct {
    ID         uuid.UUID `json:"id"`
    UserID     uuid.UUID `json:"user_id"`
    Token      string    `json:"token"`
    ExpiresAt  time.Time `json:"expires_at"`
    CreatedAt  time.Time `json:"created_at"`
    Revoked    bool      `json:"revoked"`
    DeviceInfo string    `json:"device_info,omitempty"`
}

// Request/Response DTOs
type SignupRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
    Name     string `json:"name" binding:"required,min=2"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`
}

type AuthResponse struct {
    Success      bool   `json:"success"`
    Message      string `json:"message"`
    AccessToken  string `json:"access_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    User         *User  `json:"user,omitempty"`
}