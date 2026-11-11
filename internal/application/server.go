package application

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"tenant-access-service/internal/config"
	"tenant-access-service/internal/domain"
	"tenant-access-service/internal/middleware"
	"tenant-access-service/internal/response"
	"tenant-access-service/internal/role"
	"tenant-access-service/internal/service"
	"tenant-access-service/internal/tenant"
	"tenant-access-service/internal/user"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Server struct {
	health interface{ Ping(context.Context) error }
	cfg    config.Config
	auth   *service.AuthService
	tenant *tenant.Service
	users  *user.Service
	roles  *role.Service
}

func (s *Server) Router() *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.GET("/healthz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), s.cfg.DBAcquireTime)
		defer cancel()
		if err := s.health.Ping(ctx); err != nil {
			response.Error(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Database unavailable")
			return
		}
		response.Success(c, http.StatusOK, gin.H{"status": "ok"}, "Service is healthy")
	})

	api := router.Group("/api/v1")
	api.POST("/auth/login", s.login)
	api.POST("/auth/platform-login", s.platformLogin)
	api.POST("/auth/refresh", s.refresh)
	tenantRoutes := api.Group("")
	tenantRoutes.Use(middleware.RequireAuth(s.cfg), s.validateTenantOrPlatform, validatePathID)
	tenantRoutes.GET("/tenants", s.requireTenantOrPlatformPermission("tenant:read"), s.listTenants)
	tenantRoutes.POST("/tenants", s.requirePlatformToken, s.createTenant)
	tenantRoutes.GET("/tenants/:id", s.requireTenantOrPlatformPermission("tenant:read"), s.getTenant)
	tenantRoutes.PATCH("/tenants/:id", s.requireTenantOrPlatformPermission("tenant:update"), s.updateTenant)

	platformRoutes := api.Group("/platform")
	platformRoutes.Use(middleware.RequireAuth(s.cfg), s.validatePlatformPrincipal, validatePathID)
	platformRoutes.PATCH("/users/:id", s.updateGlobalUser)

	protected := api.Group("")
	protected.Use(middleware.RequireAuth(s.cfg), s.validatePrincipal, validatePathID)
	protected.POST("/users", s.requirePermission("user:create"), s.createUser)
	protected.GET("/users", s.requirePermission("user:read"), s.listUsers)
	protected.GET("/users/:id", s.requirePermission("user:read"), s.getUser)
	protected.PATCH("/users/:id", s.requirePermission("user:update"), s.updateUser)
	protected.DELETE("/users/:id", s.requirePermission("user:delete"), s.deleteUser)
	protected.POST("/users/:id/membership", s.requirePermission("membership:create"), s.addMembership)
	protected.PUT("/users/:id/roles", s.requirePermission("assignment:manage"), s.replaceUserRoles)
	protected.DELETE("/users/:id/roles", s.requirePermission("assignment:manage"), s.removeUserRoles)

	protected.POST("/roles", s.requirePermission("role:create"), s.createRole)
	protected.GET("/roles", s.requirePermission("role:read"), s.listRoles)
	protected.GET("/roles/:id", s.requirePermission("role:read"), s.getRole)
	protected.PATCH("/roles/:id", s.requirePermission("role:update"), s.updateRole)
	protected.DELETE("/roles/:id", s.requirePermission("role:delete"), s.deleteRole)

	protected.GET("/permissions", s.requirePermission("permission:read"), s.listPermissions)
	protected.GET("/roles/:id/permissions", s.requirePermission("permission:read"), s.getRolePermissions)
	protected.PUT("/roles/:id/permissions", s.requirePermission("permission:map"), s.replaceRolePermissions)
	return router
}

func (s *Server) platformLogin(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	token, err := s.auth.PlatformLogin(ctx, input.Email, input.Password)
	if errors.Is(err, service.ErrInvalidCredentials) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid email or password")
		return
	}
	if err != nil {
		s.internalError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer"}, "Platform login successful")
}

func (s *Server) login(c *gin.Context) {
	var input struct {
		Email      string `json:"email" binding:"required,email"`
		Password   string `json:"password" binding:"required"`
		TenantCode string `json:"tenant_code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	tokens, err := s.auth.Login(ctx, service.LoginInput{
		Email: input.Email, Password: input.Password, TenantCode: input.TenantCode,
	})
	if errors.Is(err, service.ErrInvalidCredentials) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid email, password, or tenant")
		return
	}
	if err != nil {
		s.internalError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{
		"access_token": tokens.AccessToken, "refresh_token": tokens.RefreshToken, "token_type": "Bearer",
	}, "Login successful")
}

func (s *Server) refresh(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	access, err := s.auth.Refresh(ctx, input.RefreshToken)
	if errors.Is(err, service.ErrInvalidToken) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired refresh token")
		return
	}
	if errors.Is(err, service.ErrInactivePrincipal) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "User membership is no longer active")
		return
	}
	if err != nil {
		s.internalError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{"access_token": access, "token_type": "Bearer"}, "Token refreshed successfully")
}

func (s *Server) validatePrincipal(c *gin.Context) {
	session, err := middleware.ExtractAuthContext(c)
	if err != nil || session.TokenType != "access" {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		c.Abort()
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	tenantStatus, err := s.auth.ValidatePrincipal(ctx, session.TenantUserID, session.TenantID, session.UserID)
	if errors.Is(err, service.ErrInactivePrincipal) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "User membership is no longer active")
		c.Abort()
		return
	}
	if err != nil {
		s.internalError(c, err)
		c.Abort()
		return
	}
	c.Set("tenant_suspended", tenantStatus != "active")
	c.Next()
}

func (s *Server) validateTenantOrPlatform(c *gin.Context) {
	session, err := middleware.ExtractAuthContext(c)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		c.Abort()
		return
	}
	if session.TokenType == "platform_access" {
		s.validatePlatformPrincipal(c)
		return
	}
	s.validatePrincipal(c)
}

func (s *Server) validatePlatformPrincipal(c *gin.Context) {
	session, err := middleware.ExtractAuthContext(c)
	if err != nil || session.TokenType != "platform_access" {
		response.Error(c, http.StatusForbidden, "FORBIDDEN", "Platform administrator access required")
		c.Abort()
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	if err := s.auth.ValidatePlatformAdmin(ctx, session.UserID); errors.Is(err, service.ErrInactivePrincipal) {
		response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Platform administrator is no longer active")
		c.Abort()
		return
	} else if err != nil {
		s.internalError(c, err)
		c.Abort()
		return
	}
	c.Next()
}

func (s *Server) requirePlatformToken(c *gin.Context) {
	session, err := middleware.ExtractAuthContext(c)
	if err != nil || session.TokenType != "platform_access" {
		response.Error(c, http.StatusForbidden, "FORBIDDEN", "Platform administrator access required")
		c.Abort()
		return
	}
	c.Next()
}

func (s *Server) requireTenantOrPlatformPermission(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := middleware.ExtractAuthContext(c)
		if err != nil {
			response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
			c.Abort()
			return
		}
		if session.TokenType == "platform_access" {
			c.Next()
			return
		}
		s.requirePermission(required)(c)
	}
}

func (s *Server) requirePermission(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := middleware.ExtractAuthContext(c)
		if err != nil {
			response.Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
			c.Abort()
			return
		}
		suspended, _ := c.Get("tenant_suspended")
		ctx, cancel := s.dbContext(c)
		defer cancel()
		err = s.auth.Authorize(ctx, session.TenantUserID, session.TenantID, required, suspended == true)
		if errors.Is(err, service.ErrTenantSuspended) {
			response.Error(c, http.StatusForbidden, "FORBIDDEN", "Tenant is suspended")
			c.Abort()
			return
		}
		if errors.Is(err, service.ErrPermissionDenied) {
			response.Error(c, http.StatusForbidden, "FORBIDDEN", "Permission denied")
			c.Abort()
			return
		}
		if err != nil {
			s.internalError(c, err)
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) listTenants(c *gin.Context) {
	session, _ := middleware.ExtractAuthContext(c)
	ctx, cancel := s.dbContext(c)
	defer cancel()
	if session.TokenType == "platform_access" {
		limit, offset, err := parsePagination(c)
		if err != nil {
			writeError(c, err)
			return
		}
		items, err := s.tenant.ListAll(ctx, limit, offset)
		if err != nil {
			s.writeServiceError(c, err)
			return
		}
		response.Success(c, http.StatusOK, items, "Tenants fetched successfully")
		return
	}
	item, err := s.tenant.ListForMembership(ctx, session.TenantID, session.TenantUserID)
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, []tenant.Tenant{item}, "Tenants fetched successfully")
}

func (s *Server) getTenant(c *gin.Context) {
	session, _ := middleware.ExtractAuthContext(c)
	if session.TokenType != "platform_access" && c.Param("id") != session.TenantID {
		notFound(c)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.tenant.Get(ctx, c.Param("id"))
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, item, "Tenant fetched successfully")
}

func (s *Server) updateTenant(c *gin.Context) {
	session, _ := middleware.ExtractAuthContext(c)
	if session.TokenType != "platform_access" && c.Param("id") != session.TenantID {
		notFound(c)
		return
	}
	var input struct {
		Name   string `json:"name" binding:"required,max=150"`
		Code   string `json:"code" binding:"required,max=50"`
		Status string `json:"status" binding:"required,oneof=active suspended"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.tenant.Update(ctx, tenant.UpdateTenantInput{
		TenantID: c.Param("id"), ActorID: session.UserID,
		Name: input.Name, Code: input.Code, Status: input.Status,
	})
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			notFound(c)
			return
		}
		if errors.Is(err, tenant.ErrInvalidTenant) {
			writeError(c, errNoFields)
			return
		}
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusOK, gin.H{"id": item.ID, "name": item.Name, "code": item.Code, "status": item.Status}, "Tenant updated successfully")
}

func (s *Server) createTenant(c *gin.Context) {
	session, _ := middleware.ExtractAuthContext(c)
	var input struct {
		Name       string `json:"name" binding:"required,max=150"`
		Code       string `json:"code" binding:"required,max=50"`
		AdminEmail string `json:"admin_email" binding:"required,email,max=255"`
		Password   string `json:"admin_password" binding:"required,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writeError(c, err)
		return
	}
	ctx, cancel := s.dbContext(c)
	defer cancel()
	item, err := s.tenant.Create(ctx, tenant.CreateTenantInput{
		ActorID: session.UserID, Name: input.Name, Code: input.Code,
		AdminEmail: input.AdminEmail, Password: input.Password,
	})
	if err != nil {
		s.writeServiceError(c, err)
		return
	}
	response.Success(c, http.StatusCreated, item, "Tenant created successfully")
}

func (s *Server) dbContext(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), s.cfg.DBAcquireTime)
}

func validatePathID(c *gin.Context) {
	if raw := c.Param("id"); raw != "" {
		if _, err := parseID(raw); err != nil {
			writeError(c, err)
			c.Abort()
			return
		}
	}
	c.Next()
}

func currentPrincipal(c *gin.Context) domain.Actor {
	session, _ := middleware.ExtractAuthContext(c)
	return domain.Actor{
		UserID: session.UserID, TenantID: session.TenantID, MembershipID: session.TenantUserID,
	}
}

func (s *Server) internalError(c *gin.Context, err error) {
	c.Error(err)
	response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred")
}

func (s *Server) writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		notFound(c)
	case errors.Is(err, domain.ErrSharedIdentity):
		response.Error(c, http.StatusConflict, "CONFLICT", "Shared login identity must be updated by a platform administrator")
	case errors.Is(err, domain.ErrConflict):
		response.Error(c, http.StatusConflict, "CONFLICT", "A resource with the same unique value already exists")
	case errors.Is(err, domain.ErrInvalidInput), errors.Is(err, tenant.ErrInvalidTenant), errors.Is(err, tenant.ErrInvalidAdmin):
		writeError(c, err)
	default:
		s.internalError(c, err)
	}
}

func writeError(c *gin.Context, _ error) {
	response.Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "Request validation failed")
}

var errNoFields = errors.New("at least one field must be provided")

func notFound(c *gin.Context) {
	response.Error(c, http.StatusNotFound, "NOT_FOUND", "Resource not found")
}

func parsePagination(c *gin.Context) (int, int, error) {
	limit := 20
	offset := 0
	var err error
	if raw := c.Query("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, fmt.Errorf("limit must be between 1 and 100")
		}
	}
	if raw := c.Query("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return 0, 0, fmt.Errorf("offset must be zero or greater")
		}
	}
	return limit, offset, nil
}

func parseID(raw string) (string, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid ID")
	}
	return id.String(), nil
}
