package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/config"
)

func TestRequireAuthRejectsMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

	cfg := config.Config{JWTSecret: "test-secret", JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service"}
	RequireAuth(cfg)(c)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthAcceptsValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.Config{JWTSecret: "test-secret", JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service"}
	token, err := auth.NewToken(cfg, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cccccccc-cccc-cccc-cccc-cccccccccccc", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)

	RequireAuth(cfg)(c)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("RequireAuth() rejected a valid access token")
	}
}

func TestRequireAuthRejectsRefreshToken(t *testing.T) {
	cfg := config.Config{JWTSecret: "test-secret", JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service"}
	token, err := auth.NewToken(cfg,
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		"cccccccc-cccc-cccc-cccc-cccccccccccc",
		"refresh", time.Minute)
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if status := invokeAuth(t, cfg, token); status != http.StatusUnauthorized {
		t.Fatalf("refresh token status = %d; want %d", status, http.StatusUnauthorized)
	}
}

func invokeAuth(t *testing.T, cfg config.Config, token string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	context.Request.Header.Set("Authorization", "Bearer "+token)
	RequireAuth(cfg)(context)
	return recorder.Code
}
