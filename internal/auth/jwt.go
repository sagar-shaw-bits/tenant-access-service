package auth

import (
	"errors"
	"fmt"
	"time"

	"tenant-access-service/internal/config"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenClaims struct {
	UserID       string `json:"sub"`
	TenantID     string `json:"tenant_id"`
	TenantUserID string `json:"tenant_user_id"`
	TokenType    string `json:"token_type"`
	jwt.RegisteredClaims
}

func NewToken(cfg config.Config, userID, tenantID, tenantUserID, tokenType string, ttl time.Duration) (string, error) {
	claims := TokenClaims{
		UserID:       userID,
		TenantID:     tenantID,
		TenantUserID: tenantUserID,
		TokenType:    tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.JWTIssuer,
			Audience:  jwt.ClaimStrings{cfg.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func NewPlatformToken(cfg config.Config, userID string) (string, error) {
	claims := TokenClaims{
		UserID:    userID,
		TokenType: "platform_access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.JWTIssuer,
			Audience:  jwt.ClaimStrings{cfg.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign platform token: %w", err)
	}
	return signed, nil
}

func ValidateToken(cfg config.Config, rawToken string) (*TokenClaims, error) {
	parsed, err := jwt.ParseWithClaims(
		rawToken,
		&TokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(cfg.JWTIssuer),
		jwt.WithAudience(cfg.JWTAudience),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := parsed.Claims.(*TokenClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.TokenType != "access" && claims.TokenType != "refresh" && claims.TokenType != "platform_access" {
		return nil, errors.New("missing token type")
	}
	if claims.UserID == "" || claims.ID == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil {
		return nil, errors.New("required token claims are missing")
	}
	if _, err := uuid.Parse(claims.UserID); err != nil {
		return nil, errors.New("invalid subject")
	}
	if claims.TokenType == "platform_access" {
		if claims.TenantID != "" || claims.TenantUserID != "" {
			return nil, errors.New("platform token must not contain tenant claims")
		}
	} else {
		if claims.TenantID == "" || claims.TenantUserID == "" {
			return nil, errors.New("tenant claims are required")
		}
		if _, err := uuid.Parse(claims.TenantID); err != nil {
			return nil, errors.New("invalid tenant claim")
		}
		if _, err := uuid.Parse(claims.TenantUserID); err != nil {
			return nil, errors.New("invalid membership claim")
		}
	}
	return claims, nil
}
