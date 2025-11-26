package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ndyabagye/auth-service/internal/config"
	"github.com/ndyabagye/auth-service/internal/database"
	"github.com/ndyabagye/auth-service/internal/handlers"
	"github.com/ndyabagye/auth-service/internal/middleware"
	"github.com/ndyabagye/auth-service/internal/repository"
	"github.com/ndyabagye/auth-service/internal/services"
	"github.com/sirupsen/logrus"
)

func main(){
	// initialize logger
	logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    logger.SetOutput(os.Stdout)

	// load configuration
	cfg, err := config.Load()
    if err != nil {
        logger.WithError(err).Fatal("Failed to load configuration")
    }

	// set log level
	level, err := logrus.ParseLevel(cfg.Logging.Level)
    if err != nil {
        level = logrus.InfoLevel
    }
    logger.SetLevel(level)

    logger.Info("Starting authentication service")

	// connect to database
	db, err := database.NewDatabase(cfg.Database.ConnectionString(), logger)
    if err != nil {
        logger.WithError(err).Fatal("Failed to connect to database")
    }
    defer db.Close()

	// Initialize repository, service, and handler
    userRepo := repository.NewUserRepository(db.DB)
    authService := services.NewAuthService(userRepo, cfg, logger)
    authHandler := handlers.NewAuthHandler(authService, logger)

    // Setup Gin router
    if cfg.Server.Env == "production" {
        gin.SetMode(gin.ReleaseMode)
    }
    router := gin.New()

	// Middleware
    router.Use(gin.Recovery())
    router.Use(LoggerMiddleware(logger))
    router.Use(CORSMiddleware())

	// Health check
    router.GET("/health", func(c *gin.Context) {
        if err := db.Health(); err != nil {
            c.JSON(http.StatusServiceUnavailable, gin.H{
                "status": "unhealthy",
                "error":  err.Error(),
            })
            return
        }
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "time":   time.Now().Format(time.RFC3339),
        })
    })

	// API routes
    v1 := router.Group("/api/v1")
    {
        // Public routes
        auth := v1.Group("/auth")
        {
            auth.POST("/signup", authHandler.Signup)
            auth.POST("/login", authHandler.Login)
            auth.POST("/refresh", authHandler.RefreshToken)
            auth.POST("/logout", authHandler.Logout)
        }

        // Protected routes
        protected := v1.Group("/")
        protected.Use(middleware.AuthMiddleware(cfg.JWT.Secret, logger))
        {
            protected.GET("/profile", authHandler.GetProfile)
        }
    }

	// Setup HTTP server
    srv := &http.Server{
        Addr:         ":" + cfg.Server.Port,
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Start server in a goroutine
    go func() {
        logger.Infof("Server starting on port %s", cfg.Server.Port)
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.WithError(err).Fatal("Failed to start server")
        }
    }()

	// Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    logger.Info("Shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        logger.WithError(err).Fatal("Server forced to shutdown")
    }

    logger.Info("Server exited")
}


func LoggerMiddleware(logger *logrus.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        raw := c.Request.URL.RawQuery

        c.Next()

        latency := time.Since(start)
        clientIP := c.ClientIP()
        method := c.Request.Method
        statusCode := c.Writer.Status()

        if raw != "" {
            path = path + "?" + raw
        }

        logger.WithFields(logrus.Fields{
            "status":     statusCode,
            "method":     method,
            "path":       path,
            "ip":         clientIP,
            "latency_ms": latency.Milliseconds(),
        }).Info("Request processed")
    }
}

func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }

        c.Next()
    }
}