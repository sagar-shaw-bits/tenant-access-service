package auth

import (
	"testing"
	"time"

	"tenant-access-service/internal/config"
)

func TestNormalizeEmail(t *testing.T) {
	if got := NormalizeEmail("  User@Example.com  "); got != "user@example.com" {
		t.Fatalf("NormalizeEmail() = %q; want %q", got, "user@example.com")
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("P@ssw0rd")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !CheckPasswordHash("P@ssw0rd", hash) {
		t.Fatal("CheckPasswordHash() returned false for the correct password")
	}
	if CheckPasswordHash("wrong", hash) {
		t.Fatal("CheckPasswordHash() returned true for the wrong password")
	}
}

func TestTokenRoundTrip(t *testing.T) {
	cfg := config.Config{JWTSecret: "test-secret", JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service"}
	token, err := NewToken(cfg, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cccccccc-cccc-cccc-cccc-cccccccccccc", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	claims, err := ValidateToken(cfg, token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims.UserID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" ||
		claims.TenantID != "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" || claims.TokenType != "access" {
		t.Fatalf("claims mismatch: %#v", claims)
	}
}

func TestPlatformTokenHasNoTenantClaims(t *testing.T) {
	cfg := config.Config{
		JWTSecret: "test-secret", JWTIssuer: "tenant-access-service",
		JWTAudience: "tenant-access-service", AccessTTL: 15 * time.Minute,
	}
	token, err := NewPlatformToken(cfg, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewPlatformToken() error = %v", err)
	}
	claims, err := ValidateToken(cfg, token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims.TokenType != "platform_access" || claims.TenantID != "" || claims.TenantUserID != "" {
		t.Fatalf("platform token has unexpected claims: %#v", claims)
	}
}

func TestValidateTokenRejectsExpiredTokenAndWrongIssuer(t *testing.T) {
	cfg := config.Config{JWTSecret: "test-secret", JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service"}
	userID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	membershipID := "cccccccc-cccc-cccc-cccc-cccccccccccc"

	expired, err := NewToken(cfg, userID, tenantID, membershipID, "access", -time.Minute)
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if _, err := ValidateToken(cfg, expired); err == nil {
		t.Fatal("ValidateToken() accepted an expired JWT")
	}

	wrongIssuerCfg := cfg
	wrongIssuerCfg.JWTIssuer = "different-issuer"
	wrongIssuer, err := NewToken(wrongIssuerCfg, userID, tenantID, membershipID, "access", time.Minute)
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if _, err := ValidateToken(cfg, wrongIssuer); err == nil {
		t.Fatal("ValidateToken() accepted a token from a different issuer")
	}
}
