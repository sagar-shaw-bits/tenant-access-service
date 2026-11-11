package middleware

import (
	"errors"
	"net/http"
	"strings"

	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/config"

	"github.com/gin-gonic/gin"
)

type AuthContext struct {
	UserID       string
	TenantID     string
	TenantUserID string
	TokenType    string
}

const (
	contextKey = "auth_context"
)

func RequireAuth(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := bearerToken(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": err.Error()}})
			return
		}

		claims, err := auth.ValidateToken(cfg, tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "Invalid or expired token"}})
			return
		}

		if claims.TokenType != "access" && claims.TokenType != "platform_access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "Wrong token type"}})
			return
		}

		ctx := AuthContext{
			UserID:       claims.UserID,
			TenantID:     claims.TenantID,
			TenantUserID: claims.TenantUserID,
			TokenType:    claims.TokenType,
		}
		c.Set(contextKey, ctx)
		if claims.TenantID != "" {
			c.Set("tenant_id", claims.TenantID)
		}
		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func ExtractAuthContext(c *gin.Context) (AuthContext, error) {
	value, ok := c.Get(contextKey)
	if !ok {
		return AuthContext{}, errors.New("authentication context not found")
	}
	ctx, ok := value.(AuthContext)
	if !ok {
		return AuthContext{}, errors.New("invalid authentication context")
	}
	return ctx, nil
}

func bearerToken(c *gin.Context) (string, error) {
	authorization := c.GetHeader("Authorization")
	if authorization == "" {
		return "", errors.New("missing Authorization header")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", errors.New("invalid Authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}
