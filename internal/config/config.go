package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	AppEnv             string
	AppPort            string
	JWTSecret          string
	JWTIssuer          string
	JWTAudience        string
	AccessTTL          time.Duration
	RefreshTTL         time.Duration
	DBHost             string
	DBPort             int
	DBUser             string
	DBPassword         string
	DBName             string
	DBSSLMode          string
	DBMaxConns         int32
	DBMinConns         int32
	DBAcquireTime      time.Duration
	DBMaxLifetime      time.Duration
	DBMaxIdleTime      time.Duration
	PermissionCacheTTL time.Duration
}

func Load() (Config, error) {
	dbPort, err := envInt("DB_PORT", 5432)
	if err != nil {
		return Config{}, err
	}
	maxConns, err := envInt("DB_MAX_CONNS", 25)
	if err != nil {
		return Config{}, err
	}
	minConns, err := envInt("DB_MIN_CONNS", 5)
	if err != nil {
		return Config{}, err
	}
	accessTTL, err := envDuration("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	refreshTTL, err := envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	acquireTimeout, err := envDuration("DB_ACQUIRE_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	maxLifetime, err := envDuration("DB_MAX_CONN_LIFETIME", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	maxIdleTime, err := envDuration("DB_MAX_IDLE_TIME", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cacheTTL, err := envDuration("PERMISSION_CACHE_TTL", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		AppEnv:             getEnv("APP_ENV", "development"),
		AppPort:            getEnv("APP_PORT", "8080"),
		JWTSecret:          getEnv("JWT_SECRET", "change-me"),
		JWTIssuer:          getEnv("JWT_ISSUER", "tenant-access-service"),
		JWTAudience:        getEnv("JWT_AUDIENCE", "tenant-access-service"),
		AccessTTL:          accessTTL,
		RefreshTTL:         refreshTTL,
		DBHost:             getEnv("DB_HOST", "localhost"),
		DBPort:             dbPort,
		DBUser:             getEnv("DB_USER", "postgres"),
		DBPassword:         getEnv("DB_PASSWORD", "postgres"),
		DBName:             getEnv("DB_NAME", "tenant_access_service"),
		DBSSLMode:          getEnv("DB_SSLMODE", "disable"),
		DBMaxConns:         int32(maxConns),
		DBMinConns:         int32(minConns),
		DBAcquireTime:      acquireTimeout,
		DBMaxLifetime:      maxLifetime,
		DBMaxIdleTime:      maxIdleTime,
		PermissionCacheTTL: cacheTTL,
	}

	if cfg.AppEnv == "production" && (cfg.JWTSecret == "change-me" || len(cfg.JWTSecret) < 32) {
		return Config{}, fmt.Errorf("JWT_SECRET must be at least 32 characters in production")
	}
	appPort, err := strconv.Atoi(cfg.AppPort)
	if err != nil || appPort < 1 || appPort > 65535 {
		return Config{}, fmt.Errorf("APP_PORT must be between 1 and 65535")
	}
	if cfg.DBPort < 1 || cfg.DBPort > 65535 {
		return Config{}, fmt.Errorf("DB_PORT must be between 1 and 65535")
	}
	if maxConns < 1 || maxConns > int(1<<31-1) || minConns < 0 || minConns > maxConns {
		return Config{}, fmt.Errorf("database pool settings are invalid")
	}
	if cfg.AccessTTL <= 0 || cfg.RefreshTTL <= 0 || cfg.PermissionCacheTTL <= 0 ||
		cfg.DBAcquireTime <= 0 || cfg.DBMaxLifetime <= 0 || cfg.DBMaxIdleTime <= 0 {
		return Config{}, fmt.Errorf("token, database, and permission-cache lifetimes must be positive")
	}
	if cfg.JWTIssuer == "" || cfg.JWTAudience == "" {
		return Config{}, fmt.Errorf("JWT_ISSUER and JWT_AUDIENCE are required")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	value := getEnv(key, "")
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %w", key, err)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := getEnv(key, "")
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return parsed, nil
}
