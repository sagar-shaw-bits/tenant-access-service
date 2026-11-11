package role

import (
	"context"
	"strings"

	"tenant-access-service/internal/domain"
)

type Repository interface {
	CreateRole(context.Context, string, string, string) (domain.Role, error)
	ListRoles(context.Context, string, string, int, int) ([]domain.Role, error)
	GetRole(context.Context, string, string) (domain.Role, error)
	UpdateRole(context.Context, string, string, string, string) (domain.Role, error)
	DeleteRole(context.Context, string, string, string) ([]string, error)
	ListPermissions(context.Context, string, int, int) ([]domain.Permission, error)
	RolePermissions(context.Context, string, string) ([]domain.Permission, error)
	ReplaceRolePermissions(context.Context, string, string, string, []string) ([]string, error)
}

type PermissionInvalidator interface {
	Delete(string)
}

type Service struct {
	repository Repository
	cache      PermissionInvalidator
}

func NewService(repository Repository, cache PermissionInvalidator) *Service {
	return &Service{repository: repository, cache: cache}
}

func (s *Service) Create(ctx context.Context, actor domain.Actor, name string) (domain.Role, error) {
	return s.repository.CreateRole(ctx, actor.TenantID, actor.UserID, strings.TrimSpace(name))
}

func (s *Service) List(ctx context.Context, actor domain.Actor, name string, limit, offset int) (domain.Page[domain.Role], error) {
	items, err := s.repository.ListRoles(ctx, actor.TenantID, strings.TrimSpace(name), limit, offset)
	return domain.Page[domain.Role]{Items: items, Limit: limit, Offset: offset}, err
}

func (s *Service) Get(ctx context.Context, actor domain.Actor, roleID string) (domain.Role, error) {
	return s.repository.GetRole(ctx, actor.TenantID, roleID)
}

func (s *Service) Update(ctx context.Context, actor domain.Actor, roleID, name string) (domain.Role, error) {
	return s.repository.UpdateRole(ctx, actor.TenantID, actor.UserID, roleID, strings.TrimSpace(name))
}

func (s *Service) Delete(ctx context.Context, actor domain.Actor, roleID string) error {
	memberships, err := s.repository.DeleteRole(ctx, actor.TenantID, actor.UserID, roleID)
	if err != nil {
		return err
	}
	s.invalidate(memberships)
	return nil
}

func (s *Service) ListPermissions(ctx context.Context, _ domain.Actor, resource string, limit, offset int) (domain.Page[domain.Permission], error) {
	items, err := s.repository.ListPermissions(ctx, strings.TrimSpace(resource), limit, offset)
	return domain.Page[domain.Permission]{Items: items, Limit: limit, Offset: offset}, err
}

func (s *Service) Permissions(ctx context.Context, actor domain.Actor, roleID string) ([]domain.Permission, error) {
	return s.repository.RolePermissions(ctx, actor.TenantID, roleID)
}

func (s *Service) ReplacePermissions(ctx context.Context, actor domain.Actor, roleID string, permissionIDs []string) (domain.PermissionMapping, error) {
	memberships, err := s.repository.ReplaceRolePermissions(ctx, actor.TenantID, actor.UserID, roleID, permissionIDs)
	if err != nil {
		return domain.PermissionMapping{}, err
	}
	s.invalidate(memberships)
	return domain.PermissionMapping{RoleID: roleID, PermissionIDs: permissionIDs}, nil
}

func (s *Service) invalidate(membershipIDs []string) {
	if s.cache == nil {
		return
	}
	for _, id := range membershipIDs {
		s.cache.Delete(id)
	}
}
