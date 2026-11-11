package repository

import (
	"context"
	"errors"

	"tenant-access-service/internal/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Postgres struct {
	pool Pool
}

type Pool interface {
	Ping(context.Context) error
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

func NewPostgres(pool Pool) *Postgres {
	return &Postgres{pool: pool}
}

func (r *Postgres) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

func translateError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return domain.ErrConflict
	}
	return err
}

func (r *Postgres) Authenticate(ctx context.Context, email, tenantCode string) (domain.Principal, error) {
	var principal domain.Principal
	err := r.pool.QueryRow(ctx, `
		SELECT u.id, t.id, tu.id, u.password_hash, t.status
		FROM users u
		JOIN tenant_users tu ON tu.user_id = u.id
		JOIN tenants t ON t.id = tu.tenant_id
		WHERE lower(u.email) = $1 AND t.code = $2
			AND u.deleted_at IS NULL AND tu.deleted_at IS NULL`,
		email, tenantCode,
	).Scan(&principal.UserID, &principal.TenantID, &principal.MembershipID,
		&principal.PasswordHash, &principal.TenantStatus)
	return principal, translateError(err)
}

func (r *Postgres) AuthenticatePlatform(ctx context.Context, email string) (domain.Principal, error) {
	var principal domain.Principal
	err := r.pool.QueryRow(ctx, `
		SELECT u.id,u.password_hash
		FROM users u JOIN platform_admins pa ON pa.user_id=u.id
		WHERE lower(u.email)=$1 AND u.deleted_at IS NULL`, email,
	).Scan(&principal.UserID, &principal.PasswordHash)
	return principal, translateError(err)
}

func (r *Postgres) ValidatePlatformAdmin(ctx context.Context, userID string) (bool, error) {
	var allowed bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM platform_admins pa
			JOIN users u ON u.id=pa.user_id
			WHERE pa.user_id=$1 AND u.deleted_at IS NULL
		)`, userID).Scan(&allowed)
	return allowed, translateError(err)
}

func (r *Postgres) AuditLogin(ctx context.Context, tenantID, userID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return translateError(err)
	}
	defer tx.Rollback(ctx)
	if err := writeAudit(ctx, tx, tenantID, userID, "auth.login", "user", userID); err != nil {
		return translateError(err)
	}
	return translateError(tx.Commit(ctx))
}

func (r *Postgres) ValidateRefresh(ctx context.Context, membershipID, tenantID, userID string) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx, `
		SELECT t.status = 'active'
		FROM users u
		JOIN tenant_users tu ON tu.user_id = u.id AND tu.id = $1 AND tu.tenant_id = $2
		JOIN tenants t ON t.id = tu.tenant_id
		WHERE u.id = $3 AND u.deleted_at IS NULL AND tu.deleted_at IS NULL`,
		membershipID, tenantID, userID,
	).Scan(&active)
	return active, translateError(err)
}

func (r *Postgres) ValidatePrincipal(ctx context.Context, membershipID, tenantID, userID string) (string, error) {
	var status string
	err := r.pool.QueryRow(ctx, `
		SELECT t.status
		FROM users u
		JOIN tenant_users tu ON tu.user_id = u.id AND tu.id = $1 AND tu.tenant_id = $2
		JOIN tenants t ON t.id = tu.tenant_id
		WHERE u.id = $3 AND u.deleted_at IS NULL AND tu.deleted_at IS NULL`,
		membershipID, tenantID, userID,
	).Scan(&status)
	return status, translateError(err)
}

func (r *Postgres) Permissions(ctx context.Context, membershipID, tenantID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id AND rp.tenant_id = ur.tenant_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.tenant_user_id = $1 AND ur.tenant_id = $2`,
		membershipID, tenantID,
	)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	permissions := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, translateError(err)
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (r *Postgres) TenantForMembership(ctx context.Context, tenantID, membershipID string) (domain.Tenant, error) {
	var tenant domain.Tenant
	err := r.pool.QueryRow(ctx, `
		SELECT t.id,t.name,t.code,t.status,t.created_at,t.updated_at
		FROM tenants t JOIN tenant_users tu ON tu.tenant_id=t.id
		WHERE t.id=$1 AND tu.id=$2 AND tu.deleted_at IS NULL`,
		tenantID, membershipID,
	).Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt)
	return tenant, translateError(err)
}

func (r *Postgres) TenantByID(ctx context.Context, tenantID string) (domain.Tenant, error) {
	var tenant domain.Tenant
	err := r.pool.QueryRow(ctx, `
		SELECT id,name,code,status,created_at,updated_at FROM tenants WHERE id=$1`,
		tenantID,
	).Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt)
	return tenant, translateError(err)
}

func (r *Postgres) ListTenants(ctx context.Context, limit, offset int) ([]domain.Tenant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,name,code,status,created_at,updated_at
		FROM tenants ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	items := make([]domain.Tenant, 0)
	for rows.Next() {
		var item domain.Tenant
		if err := rows.Scan(&item.ID, &item.Name, &item.Code, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, translateError(err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Postgres) CreateTenant(ctx context.Context, tenant domain.Tenant, actorID, adminEmail, passwordHash string) (domain.Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.Tenant{}, translateError(err)
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (id,name,code,status) VALUES ($1,$2,$3,'active')
		RETURNING id,name,code,status,created_at,updated_at`,
		tenant.ID, tenant.Name, tenant.Code,
	).Scan(&tenant.ID, &tenant.Name, &tenant.Code, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err != nil {
		return domain.Tenant{}, translateError(err)
	}
	userID, membershipID, roleID := uuid.New(), uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO users (id,email,password_hash) VALUES ($1,$2,$3)`,
		userID, adminEmail, passwordHash); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_users (id,tenant_id,user_id) VALUES ($1,$2,$3)`,
		membershipID, tenant.ID, userID); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO roles (id,tenant_id,name) VALUES ($1,$2,'tenant-admin')`,
		roleID, tenant.ID); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	permissionIDs, err := stringRows(ctx, tx, `SELECT id FROM permissions ORDER BY id`)
	if err != nil {
		return domain.Tenant{}, translateError(err)
	}
	for _, permissionID := range permissionIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (tenant_id,role_id,permission_id) VALUES ($1,$2,$3)`,
			tenant.ID, roleID, permissionID); err != nil {
			return domain.Tenant{}, translateError(err)
		}
		if err := writeAudit(ctx, tx, tenant.ID, actorID, "permission.map", "permission", permissionID); err != nil {
			return domain.Tenant{}, translateError(err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_roles (tenant_id,tenant_user_id,role_id) VALUES ($1,$2,$3)`,
		tenant.ID, membershipID, roleID); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	for _, audit := range []struct {
		action, targetType, targetID string
	}{
		{"tenant.create", "tenant", tenant.ID},
		{"user.create", "user", userID.String()},
		{"membership.create", "membership", membershipID.String()},
		{"role.create", "role", roleID.String()},
	} {
		if err := writeAudit(ctx, tx, tenant.ID, actorID, audit.action, audit.targetType, audit.targetID); err != nil {
			return domain.Tenant{}, translateError(err)
		}
	}
	if err := writeAssignmentAudit(ctx, tx, tenant.ID, actorID, "assignment.add", membershipID.String(), roleID.String()); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Tenant{}, translateError(err)
	}
	return tenant, nil
}

func (r *Postgres) UpdateTenant(ctx context.Context, tenant domain.Tenant, actorID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return translateError(err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE tenants SET name=$1,code=$2,status=$3,updated_at=NOW() WHERE id=$4`,
		tenant.Name, tenant.Code, tenant.Status, tenant.ID,
	)
	if err != nil {
		return translateError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	if err := writeAudit(ctx, tx, tenant.ID, actorID, "tenant.update", "tenant", tenant.ID); err != nil {
		return translateError(err)
	}
	return translateError(tx.Commit(ctx))
}
