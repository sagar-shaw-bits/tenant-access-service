package user

import (
	"context"

	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/domain"
)

type Repository interface {
	CreateUser(context.Context, string, string, string, string) (domain.User, error)
	ListUsers(context.Context, string, string, int, int) ([]domain.User, error)
	GetUser(context.Context, string, string) (domain.User, error)
	UpdateUser(context.Context, string, string, string, string, string) (domain.User, error)
	UpdateGlobalUser(context.Context, string, string, string, string) (domain.User, error)
	DeleteUser(context.Context, string, string, string) (string, error)
	CreateMembership(context.Context, string, string, string) (string, error)
	ChangeUserRoles(context.Context, string, string, string, []string, bool) (string, error)
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

func (s *Service) Create(ctx context.Context, actor domain.Actor, email, password string) (domain.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return domain.User{}, err
	}
	return s.repository.CreateUser(ctx, actor.TenantID, actor.UserID, auth.NormalizeEmail(email), hash)
}

func (s *Service) List(ctx context.Context, actor domain.Actor, email string, limit, offset int) (domain.Page[domain.User], error) {
	items, err := s.repository.ListUsers(ctx, actor.TenantID, auth.NormalizeEmail(email), limit, offset)
	return domain.Page[domain.User]{Items: items, Limit: limit, Offset: offset}, err
}

func (s *Service) Get(ctx context.Context, actor domain.Actor, userID string) (domain.User, error) {
	return s.repository.GetUser(ctx, actor.TenantID, userID)
}

func (s *Service) Update(ctx context.Context, actor domain.Actor, userID string, email, password *string) (domain.User, error) {
	normalizedEmail, passwordHash, err := prepareUpdate(email, password)
	if err != nil {
		return domain.User{}, err
	}
	return s.repository.UpdateUser(ctx, actor.TenantID, actor.UserID, userID, normalizedEmail, passwordHash)
}

func (s *Service) UpdateGlobal(ctx context.Context, actorID, userID string, email, password *string) (domain.User, error) {
	normalizedEmail, passwordHash, err := prepareUpdate(email, password)
	if err != nil {
		return domain.User{}, err
	}
	return s.repository.UpdateGlobalUser(ctx, actorID, userID, normalizedEmail, passwordHash)
}

func (s *Service) Delete(ctx context.Context, actor domain.Actor, userID string) error {
	membershipID, err := s.repository.DeleteUser(ctx, actor.TenantID, actor.UserID, userID)
	if err != nil {
		return err
	}
	if s.cache != nil {
		s.cache.Delete(membershipID)
	}
	return nil
}

type Membership struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
}

func (s *Service) AddMembership(ctx context.Context, actor domain.Actor, userID string) (Membership, error) {
	id, err := s.repository.CreateMembership(ctx, actor.TenantID, actor.UserID, userID)
	return Membership{ID: id, UserID: userID}, err
}

func (s *Service) ChangeRoles(ctx context.Context, actor domain.Actor, userID string, roleIDs []string, replace bool) (domain.RoleAssignments, error) {
	membershipID, err := s.repository.ChangeUserRoles(ctx, actor.TenantID, actor.UserID, userID, roleIDs, replace)
	if err != nil {
		return domain.RoleAssignments{}, err
	}
	if s.cache != nil {
		s.cache.Delete(membershipID)
	}
	return domain.RoleAssignments{UserID: userID, RoleIDs: roleIDs}, nil
}

func prepareUpdate(email, password *string) (string, string, error) {
	normalizedEmail := ""
	if email != nil {
		normalizedEmail = auth.NormalizeEmail(*email)
		if normalizedEmail == "" {
			return "", "", domain.ErrInvalidInput
		}
	}
	passwordHash := ""
	if password != nil {
		var err error
		passwordHash, err = auth.HashPassword(*password)
		if err != nil {
			return "", "", err
		}
	}
	return normalizedEmail, passwordHash, nil
}
