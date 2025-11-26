package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	_ "github.com/lib/pq"
)

type Database struct {
	DB *sql.DB
	logger *logrus.Logger
}

func NewDatabase(connString string, logger *logrus.Logger) (*Database, error){
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	// test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("Database connection established successfully")

	return &Database{
        DB:     db,
        logger: logger,
    }, nil
}

func (d *Database) Close() error {
    d.logger.Info("Closing database connection")
    return d.DB.Close()
}

func (d *Database) Health() error {
    return d.DB.Ping()
}