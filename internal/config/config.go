package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Security SecurityConfig
	Logging  LoggingConfig
}

type ServerConfig struct {
	Port string
	Env  string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
}

type JWTConfig struct {
	Secret             string
	Expiry             time.Duration
	RefreshTokenExpiry time.Duration
}

type SecurityConfig struct {
	BcryptCost int
}

type LoggingConfig struct {
	Level string
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	dbPort, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	jwtExpiry, err := time.ParseDuration(getEnv("JWT_EXPIRY", "24h"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_EXPIRY: %w", err)
	}

	refreshExpiry, err := time.ParseDuration(getEnv("REFRESH_TOKEN_EXPIRY", "720h"))
	if err != nil {
		return nil, fmt.Errorf("invalid REFRESH_TOKEN_EXPIRY: %w", err)
	}

	bcryptCost, err := strconv.Atoi(getEnv("BCRYPT_COST", "10"))
	if err != nil {
		return nil, fmt.Errorf("invalid BCRYPT_COST: %w", err)
	}

	return &Config{
		Server: ServerConfig{
			Port: getEnv("PORT", "8080"),
			Env:  getEnv("ENV", "development"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     dbPort,
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", "auth_system"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		JWT: JWTConfig{
			Secret:             getEnv("JWT_SECRET", "change-this-secret"),
			Expiry:             jwtExpiry,
			RefreshTokenExpiry: refreshExpiry,
		},
		Security: SecurityConfig{
			BcryptCost: bcryptCost,
		},
		Logging: LoggingConfig{
			Level: getEnv("LOG_LEVEL", "info"),
		},
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (c *DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}
