package tenant

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/domain"
)

var (
	ErrInvalidTenant = errors.New("tenant name and code are required")
	ErrInvalidAdmin  = errors.New("initial tenant administrator is required")
)

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Code      string    `json:"code"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Repository interface {
	TenantForMembership(context.Context, string, string) (domain.Tenant, error)
	TenantByID(context.Context, string) (domain.Tenant, error)
	ListTenants(context.Context, int, int) ([]domain.Tenant, error)
	CreateTenant(context.Context, domain.Tenant, string, string, string) (domain.Tenant, error)
	UpdateTenant(context.Context, domain.Tenant, string) error
}

func (s *Service) ListAll(ctx context.Context, limit, offset int) (domain.Page[Tenant], error) {
	records, err := s.repository.ListTenants(ctx, limit, offset)
	if err != nil {
		return domain.Page[Tenant]{}, err
	}
	items := make([]Tenant, 0, len(records))
	for _, record := range records {
		items = append(items, tenantResult(record))
	}
	return domain.Page[Tenant]{Items: items, Limit: limit, Offset: offset}, nil
}

type CreateTenantInput struct {
	ActorID    string
	Name       string
	Code       string
	AdminEmail string
	Password   string
}

func (s *Service) Create(ctx context.Context, input CreateTenantInput) (Tenant, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Code = strings.TrimSpace(input.Code)
	input.AdminEmail = auth.NormalizeEmail(input.AdminEmail)
	if input.Name == "" || input.Code == "" {
		return Tenant{}, ErrInvalidTenant
	}
	if input.AdminEmail == "" || len(input.Password) < 8 || len(input.Password) > 72 {
		return Tenant{}, ErrInvalidAdmin
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return Tenant{}, err
	}
	record := domain.Tenant{ID: uuid.NewString(), Name: input.Name, Code: input.Code}
	record, err = s.repository.CreateTenant(ctx, record, input.ActorID, input.AdminEmail, passwordHash)
	if err != nil {
		return Tenant{}, err
	}
	return tenantResult(record), nil
}

type Service struct {
	repository Repository
}

func NewService(repo Repository) *Service {
	return &Service{repository: repo}
}

func (s *Service) ListForMembership(ctx context.Context, tenantID, membershipID string) (Tenant, error) {
	record, err := s.repository.TenantForMembership(ctx, tenantID, membershipID)
	if errors.Is(err, domain.ErrNotFound) {
		return Tenant{}, domain.ErrNotFound
	}
	return tenantResult(record), err
}

func (s *Service) Get(ctx context.Context, tenantID string) (Tenant, error) {
	record, err := s.repository.TenantByID(ctx, tenantID)
	if errors.Is(err, domain.ErrNotFound) {
		return Tenant{}, domain.ErrNotFound
	}
	return tenantResult(record), err
}

type UpdateTenantInput struct {
	TenantID string
	ActorID  string
	Name     string
	Code     string
	Status   string
}

func (s *Service) Update(ctx context.Context, input UpdateTenantInput) (Tenant, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Code = strings.TrimSpace(input.Code)
	if input.Name == "" || input.Code == "" {
		return Tenant{}, ErrInvalidTenant
	}
	record := domain.Tenant{
		ID: input.TenantID, Name: input.Name, Code: input.Code, Status: input.Status,
	}
	if err := s.repository.UpdateTenant(ctx, record, input.ActorID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Tenant{}, domain.ErrNotFound
		}
		return Tenant{}, err
	}
	return tenantResult(record), nil
}

func tenantResult(record domain.Tenant) Tenant {
	return Tenant{
		ID: record.ID, Name: record.Name, Code: record.Code, Status: record.Status,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}
