package database

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"tenant-access-service/internal/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.DBUser, cfg.DBPassword),
		Host:   net.JoinHostPort(cfg.DBHost, fmt.Sprint(cfg.DBPort)),
		Path:   "/" + cfg.DBName,
	}
	query := dsn.Query()
	query.Set("sslmode", cfg.DBSSLMode)
	dsn.RawQuery = query.Encode()
	connString := dsn.String()
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	poolConfig.MaxConns = cfg.DBMaxConns
	poolConfig.MinConns = cfg.DBMinConns
	poolConfig.MaxConnLifetime = cfg.DBMaxLifetime
	poolConfig.MaxConnIdleTime = cfg.DBMaxIdleTime
	poolConfig.ConnConfig.ConnectTimeout = cfg.DBAcquireTime
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return pool, nil
}
