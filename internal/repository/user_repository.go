package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ndyabagye/auth-service/internal/models"
)

type UserRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
    query := `
        INSERT INTO users (email, password_hash, name, is_verified)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at, updated_at
    `
    err := r.db.QueryRow(query, user.Email, user.PasswordHash, user.Name, user.IsVerified).
        Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
    
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    return nil
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, name, is_verified, created_at, updated_at
        FROM users WHERE email = $1
    `
    user := &models.User{}
    err := r.db.QueryRow(query, email).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.Name,
        &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("failed to find user: %w", err)
    }
    return user, nil
}

func (r *UserRepository) FindByID(id uuid.UUID) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, name, is_verified, created_at, updated_at
        FROM users WHERE id = $1
    `
    user := &models.User{}
    err := r.db.QueryRow(query, id).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.Name,
        &user.IsVerified, &user.CreatedAt, &user.UpdatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("failed to find user: %w", err)
    }
    return user, nil
}

func (r *UserRepository) StoreRefreshToken(token *models.RefreshToken) error {
    query := `
        INSERT INTO refresh_tokens (user_id, token, expires_at, device_info)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at
    `
    err := r.db.QueryRow(query, token.UserID, token.Token, token.ExpiresAt, token.DeviceInfo).
        Scan(&token.ID, &token.CreatedAt)
    
    if err != nil {
        return fmt.Errorf("failed to store refresh token: %w", err)
    }
    return nil
}

func (r *UserRepository) FindRefreshToken(token string) (*models.RefreshToken, error) {
    query := `
        SELECT id, user_id, token, expires_at, created_at, revoked, device_info
        FROM refresh_tokens WHERE token = $1
    `
    rt := &models.RefreshToken{}
    err := r.db.QueryRow(query, token).Scan(
        &rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt,
        &rt.CreatedAt, &rt.Revoked, &rt.DeviceInfo,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("failed to find refresh token: %w", err)
    }
    return rt, nil
}

func (r *UserRepository) RevokeRefreshToken(token string) error {
    query := `UPDATE refresh_tokens SET revoked = true WHERE token = $1`
    _, err := r.db.Exec(query, token)
    if err != nil {
        return fmt.Errorf("failed to revoke refresh token: %w", err)
    }
    return nil
}

func (r *UserRepository) DeleteExpiredTokens() error {
    query := `DELETE FROM refresh_tokens WHERE expires_at < $1`
    _, err := r.db.Exec(query, time.Now())
    if err != nil {
        return fmt.Errorf("failed to delete expired tokens: %w", err)
    }
    return nil
}