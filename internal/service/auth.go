package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/config"
	"tenant-access-service/internal/domain"
)

var (
	ErrInvalidCredentials = errors.New("invalid email, password, or tenant")
	ErrInactivePrincipal  = errors.New("user membership is no longer active")
	ErrInvalidToken       = errors.New("invalid or expired refresh token")
	ErrTenantSuspended    = errors.New("tenant is suspended")
	ErrPermissionDenied   = errors.New("permission denied")
)

type AuthRepository interface {
	Authenticate(context.Context, string, string) (domain.Principal, error)
	AuthenticatePlatform(context.Context, string) (domain.Principal, error)
	AuditLogin(context.Context, string, string) error
	ValidatePlatformAdmin(context.Context, string) (bool, error)
	ValidateRefresh(context.Context, string, string, string) (bool, error)
	ValidatePrincipal(context.Context, string, string, string) (string, error)
	Permissions(context.Context, string, string) ([]string, error)
}

type AuthService struct {
	repository AuthRepository
	config     config.Config
	cache      EffectivePermissionCache
}

type EffectivePermissionCache interface {
	Get(string) ([]string, bool)
	Set(string, []string, time.Duration)
}

func NewAuthService(repo AuthRepository, cfg config.Config, cache EffectivePermissionCache) *AuthService {
	return &AuthService{repository: repo, config: cfg, cache: cache}
}

type LoginInput struct {
	Email      string
	Password   string
	TenantCode string
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (TokenPair, error) {
	principal, err := s.repository.Authenticate(ctx, auth.NormalizeEmail(input.Email), strings.TrimSpace(input.TenantCode))
	if errors.Is(err, domain.ErrNotFound) {
		auth.CheckPasswordHash(input.Password, "$2a$10$IbMZwYN6352E/k.eVfB9.epKqTWFKKomnYvO7Dz0/pHUFaHiEyy4C")
		return TokenPair{}, ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, err
	}
	if !auth.CheckPasswordHash(input.Password, principal.PasswordHash) || principal.TenantStatus != "active" {
		return TokenPair{}, ErrInvalidCredentials
	}
	access, err := auth.NewToken(s.config, principal.UserID, principal.TenantID, principal.MembershipID, "access", s.config.AccessTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := auth.NewToken(s.config, principal.UserID, principal.TenantID, principal.MembershipID, "refresh", s.config.RefreshTTL)
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.repository.AuditLogin(ctx, principal.TenantID, principal.UserID); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func (s *AuthService) PlatformLogin(ctx context.Context, email, password string) (string, error) {
	principal, err := s.repository.AuthenticatePlatform(ctx, auth.NormalizeEmail(email))
	if errors.Is(err, domain.ErrNotFound) {
		auth.CheckPasswordHash(password, "$2a$10$IbMZwYN6352E/k.eVfB9.epKqTWFKKomnYvO7Dz0/pHUFaHiEyy4C")
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", err
	}
	if !auth.CheckPasswordHash(password, principal.PasswordHash) {
		return "", ErrInvalidCredentials
	}
	token, err := auth.NewPlatformToken(s.config, principal.UserID)
	if err != nil {
		return "", err
	}
	if err := s.repository.AuditLogin(ctx, "", principal.UserID); err != nil {
		return "", err
	}
	return token, nil
}

func (s *AuthService) ValidatePlatformAdmin(ctx context.Context, userID string) error {
	allowed, err := s.repository.ValidatePlatformAdmin(ctx, userID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrInactivePrincipal
	}
	return nil
}

func (s *AuthService) Refresh(ctx context.Context, rawToken string) (string, error) {
	claims, err := auth.ValidateToken(s.config, rawToken)
	if err != nil || claims.TokenType != "refresh" {
		return "", ErrInvalidToken
	}
	active, err := s.repository.ValidateRefresh(ctx, claims.TenantUserID, claims.TenantID, claims.UserID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && !active) {
		return "", ErrInactivePrincipal
	}
	if err != nil {
		return "", err
	}
	return auth.NewToken(s.config, claims.UserID, claims.TenantID, claims.TenantUserID, "access", s.config.AccessTTL)
}

func (s *AuthService) ValidatePrincipal(ctx context.Context, membershipID, tenantID, userID string) (string, error) {
	status, err := s.repository.ValidatePrincipal(ctx, membershipID, tenantID, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return "", ErrInactivePrincipal
	}
	return status, err
}

func (s *AuthService) HasPermission(ctx context.Context, membershipID, tenantID, required string) (bool, error) {
	permissions, cached := s.cache.Get(membershipID)
	if !cached {
		var err error
		permissions, err = s.repository.Permissions(ctx, membershipID, tenantID)
		if err != nil {
			return false, err
		}
		s.cache.Set(membershipID, permissions, s.config.PermissionCacheTTL)
	}
	for _, permission := range permissions {
		if permission == required {
			return true, nil
		}
	}
	return false, nil
}

func (s *AuthService) Authorize(ctx context.Context, membershipID, tenantID, required string, tenantSuspended bool) error {
	if tenantSuspended && required != "tenant:update" {
		return ErrTenantSuspended
	}
	allowed, err := s.HasPermission(ctx, membershipID, tenantID, required)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}
