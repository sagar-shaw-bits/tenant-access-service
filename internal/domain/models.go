package domain

import "time"

type Actor struct {
	UserID       string
	TenantID     string
	MembershipID string
}

type Principal struct {
	UserID       string
	TenantID     string
	MembershipID string
	PasswordHash string
	TenantStatus string
}

type Tenant struct {
	ID        string
	Name      string
	Code      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	ID           string     `json:"id"`
	TenantUserID string     `json:"tenant_user_id,omitempty"`
	Email        string     `json:"email"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

type Role struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type Page[T any] struct {
	Items  []T `json:"items"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type RoleAssignments struct {
	UserID  string   `json:"user_id"`
	RoleIDs []string `json:"role_ids"`
}

type PermissionMapping struct {
	RoleID        string   `json:"role_id"`
	PermissionIDs []string `json:"permission_ids"`
}
