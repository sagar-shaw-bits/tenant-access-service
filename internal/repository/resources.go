package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"tenant-access-service/internal/domain"
)

func (r *Postgres) CreateUser(ctx context.Context, tenantID, actorID, email, passwordHash string) (domain.User, error) {
	userID, membershipID := uuid.New(), uuid.New()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO users (id,email,password_hash) VALUES ($1,$2,$3)`,
		userID, email, passwordHash)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO tenant_users (id,tenant_id,user_id) VALUES ($1,$2,$3)`,
		membershipID, tenantID, userID)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "user.create", "user", userID.String()); err != nil {
		return domain.User{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, translateError(err)
	}
	return domain.User{ID: userID.String(), TenantUserID: membershipID.String(), Email: email}, nil
}

func (r *Postgres) ListUsers(ctx context.Context, tenantID, email string, limit, offset int) ([]domain.User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT u.id,tu.id,u.email,u.created_at,u.updated_at
		FROM users u JOIN tenant_users tu ON tu.user_id=u.id
		WHERE tu.tenant_id=$1 AND u.deleted_at IS NULL AND tu.deleted_at IS NULL
			AND ($2='' OR lower(u.email) LIKE $3)
		ORDER BY u.created_at DESC,u.id LIMIT $4 OFFSET $5`,
		tenantID, email, email+"%", limit, offset)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	items := make([]domain.User, 0)
	for rows.Next() {
		var item domain.User
		if err := rows.Scan(&item.ID, &item.TenantUserID, &item.Email, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, translateError(err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Postgres) GetUser(ctx context.Context, tenantID, userID string) (domain.User, error) {
	var item domain.User
	err := r.pool.QueryRow(ctx, `
		SELECT u.id,tu.id,u.email,u.created_at,u.updated_at
		FROM users u JOIN tenant_users tu ON tu.user_id=u.id
		WHERE u.id=$1 AND tu.tenant_id=$2 AND u.deleted_at IS NULL AND tu.deleted_at IS NULL`,
		userID, tenantID,
	).Scan(&item.ID, &item.TenantUserID, &item.Email, &item.CreatedAt, &item.UpdatedAt)
	return item, translateError(err)
}

func (r *Postgres) UpdateUser(ctx context.Context, tenantID, actorID, userID, email, passwordHash string) (domain.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	defer tx.Rollback(ctx)
	var lockedUserID string
	if err := tx.QueryRow(ctx, `
		SELECT u.id FROM users u
		WHERE u.id=$1 AND u.deleted_at IS NULL
			AND EXISTS (SELECT 1 FROM tenant_users tu WHERE tu.user_id=u.id AND tu.tenant_id=$2 AND tu.deleted_at IS NULL)
		FOR UPDATE OF u`, userID, tenantID).Scan(&lockedUserID); err != nil {
		return domain.User{}, translateError(err)
	}
	var activeMemberships int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM tenant_users WHERE user_id=$1 AND deleted_at IS NULL`, lockedUserID,
	).Scan(&activeMemberships); err != nil {
		return domain.User{}, translateError(err)
	}
	if activeMemberships > 1 {
		return domain.User{}, domain.ErrSharedIdentity
	}
	var item domain.User
	err = tx.QueryRow(ctx, `
		UPDATE users u
		SET email=COALESCE(NULLIF($1,''),u.email),
		    password_hash=COALESCE(NULLIF($2,''),u.password_hash),updated_at=NOW()
		WHERE u.id=$3 AND u.deleted_at IS NULL
		  AND EXISTS(SELECT 1 FROM tenant_users tu WHERE tu.user_id=u.id AND tu.tenant_id=$4 AND tu.deleted_at IS NULL)
		RETURNING u.id,u.email,u.created_at,u.updated_at`,
		email, passwordHash, userID, tenantID,
	).Scan(&item.ID, &item.Email, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "user.update", "user", item.ID); err != nil {
		return domain.User{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, translateError(err)
	}
	return item, nil
}

func (r *Postgres) UpdateGlobalUser(ctx context.Context, actorID, userID, email, passwordHash string) (domain.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	defer tx.Rollback(ctx)
	var item domain.User
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET email=COALESCE(NULLIF($1,''),email),
		    password_hash=COALESCE(NULLIF($2,''),password_hash),updated_at=NOW()
		WHERE id=$3 AND deleted_at IS NULL
		RETURNING id,email,created_at,updated_at`,
		email, passwordHash, userID,
	).Scan(&item.ID, &item.Email, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.User{}, translateError(err)
	}
	if err := writeAudit(ctx, tx, "", actorID, "user.update", "user", item.ID); err != nil {
		return domain.User{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, translateError(err)
	}
	return item, nil
}

func (r *Postgres) DeleteUser(ctx context.Context, tenantID, actorID, userID string) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", translateError(err)
	}
	defer tx.Rollback(ctx)
	var membershipID string
	err = tx.QueryRow(ctx, `
		UPDATE tenant_users SET deleted_at=NOW()
		WHERE user_id=$1 AND tenant_id=$2 AND deleted_at IS NULL
		RETURNING id`, userID, tenantID).Scan(&membershipID)
	if err != nil {
		return "", translateError(err)
	}
	roleIDs, err := stringRows(ctx, tx,
		`SELECT role_id FROM user_roles WHERE tenant_user_id=$1 AND tenant_id=$2`, membershipID, tenantID)
	if err != nil {
		return "", translateError(err)
	}
	for _, roleID := range roleIDs {
		if err := writeAssignmentAudit(ctx, tx, tenantID, actorID, "assignment.remove", membershipID, roleID); err != nil {
			return "", translateError(err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE tenant_user_id=$1 AND tenant_id=$2`, membershipID, tenantID); err != nil {
		return "", translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "user.delete", "membership", membershipID); err != nil {
		return "", translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", translateError(err)
	}
	return membershipID, nil
}

func (r *Postgres) CreateMembership(ctx context.Context, tenantID, actorID, userID string) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", translateError(err)
	}
	defer tx.Rollback(ctx)
	var existingUserID string
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, userID).Scan(&existingUserID); err != nil {
		return "", translateError(err)
	}
	var membershipID string
	var deletedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT id,deleted_at FROM tenant_users WHERE tenant_id=$1 AND user_id=$2`,
		tenantID, userID).Scan(&membershipID, &deletedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		membershipID = uuid.NewString()
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_users (id,tenant_id,user_id) VALUES ($1,$2,$3)`,
			membershipID, tenantID, userID); err != nil {
			return "", translateError(err)
		}
	case err != nil:
		return "", translateError(err)
	case deletedAt == nil:
		return "", domain.ErrConflict
	default:
		if _, err := tx.Exec(ctx, `UPDATE tenant_users SET deleted_at=NULL WHERE id=$1`, membershipID); err != nil {
			return "", translateError(err)
		}
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "membership.create", "membership", membershipID); err != nil {
		return "", translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", translateError(err)
	}
	return membershipID, nil
}

func (r *Postgres) ChangeUserRoles(ctx context.Context, tenantID, actorID, userID string, roleIDs []string, replace bool) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", translateError(err)
	}
	defer tx.Rollback(ctx)
	var membershipID string
	if err := tx.QueryRow(ctx, `
		SELECT id FROM tenant_users WHERE user_id=$1 AND tenant_id=$2 AND deleted_at IS NULL
		AND EXISTS(SELECT 1 FROM users WHERE id=$1 AND deleted_at IS NULL)`,
		userID, tenantID).Scan(&membershipID); err != nil {
		return "", translateError(err)
	}
	for _, roleID := range roleIDs {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND tenant_id=$2)`,
			roleID, tenantID).Scan(&exists); err != nil {
			return "", translateError(err)
		}
		if !exists {
			return "", domain.ErrNotFound
		}
	}
	rows, err := tx.Query(ctx, `SELECT role_id FROM user_roles WHERE tenant_user_id=$1 AND tenant_id=$2`, membershipID, tenantID)
	if err != nil {
		return "", translateError(err)
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			rows.Close()
			return "", translateError(err)
		}
		existing[roleID] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", translateError(err)
	}
	rows.Close()
	target := make(map[string]bool, len(roleIDs))
	for _, id := range roleIDs {
		target[id] = true
	}
	for oldID := range existing {
		remove := replace && !target[oldID] || !replace && target[oldID]
		if !remove {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE tenant_user_id=$1 AND role_id=$2 AND tenant_id=$3`,
			membershipID, oldID, tenantID); err != nil {
			return "", translateError(err)
		}
		if err := writeAssignmentAudit(ctx, tx, tenantID, actorID, "assignment.remove", membershipID, oldID); err != nil {
			return "", translateError(err)
		}
	}
	if replace {
		for _, id := range roleIDs {
			if existing[id] {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO user_roles (tenant_id,tenant_user_id,role_id) VALUES ($1,$2,$3)`,
				tenantID, membershipID, id); err != nil {
				return "", translateError(err)
			}
			if err := writeAssignmentAudit(ctx, tx, tenantID, actorID, "assignment.add", membershipID, id); err != nil {
				return "", translateError(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", translateError(err)
	}
	return membershipID, nil
}

func (r *Postgres) CreateRole(ctx context.Context, tenantID, actorID, name string) (domain.Role, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.Role{}, translateError(err)
	}
	defer tx.Rollback(ctx)
	var item domain.Role
	err = tx.QueryRow(ctx, `
		INSERT INTO roles(id,tenant_id,name) VALUES($1,$2,$3)
		RETURNING id,tenant_id,name,created_at,updated_at`,
		uuid.New(), tenantID, name,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.Role{}, translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "role.create", "role", item.ID); err != nil {
		return domain.Role{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Role{}, translateError(err)
	}
	return item, nil
}

func (r *Postgres) ListRoles(ctx context.Context, tenantID, name string, limit, offset int) ([]domain.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,tenant_id,name,created_at,updated_at FROM roles
		WHERE tenant_id=$1 AND ($2='' OR lower(name) LIKE lower($3))
		ORDER BY name,id LIMIT $4 OFFSET $5`,
		tenantID, name, "%"+name+"%", limit, offset)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	items := make([]domain.Role, 0)
	for rows.Next() {
		var item domain.Role
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, translateError(err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Postgres) GetRole(ctx context.Context, tenantID, roleID string) (domain.Role, error) {
	var item domain.Role
	err := r.pool.QueryRow(ctx, `
		SELECT id,tenant_id,name,created_at,updated_at FROM roles WHERE id=$1 AND tenant_id=$2`,
		roleID, tenantID,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	return item, translateError(err)
}

func (r *Postgres) UpdateRole(ctx context.Context, tenantID, actorID, roleID, name string) (domain.Role, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.Role{}, translateError(err)
	}
	defer tx.Rollback(ctx)
	var item domain.Role
	err = tx.QueryRow(ctx, `
		UPDATE roles SET name=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3
		RETURNING id,tenant_id,name,created_at,updated_at`,
		name, roleID, tenantID,
	).Scan(&item.ID, &item.TenantID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.Role{}, translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "role.update", "role", item.ID); err != nil {
		return domain.Role{}, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Role{}, translateError(err)
	}
	return item, nil
}

func (r *Postgres) DeleteRole(ctx context.Context, tenantID, actorID, roleID string) ([]string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, translateError(err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND tenant_id=$2)`, roleID, tenantID).Scan(&exists); err != nil {
		return nil, translateError(err)
	}
	if !exists {
		return nil, domain.ErrNotFound
	}
	membershipIDs, err := stringRows(ctx, tx,
		`SELECT tenant_user_id FROM user_roles WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID)
	if err != nil {
		return nil, translateError(err)
	}
	permissionIDs, err := stringRows(ctx, tx,
		`SELECT permission_id FROM role_permissions WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID)
	if err != nil {
		return nil, translateError(err)
	}
	for _, membershipID := range membershipIDs {
		if err := writeAssignmentAudit(ctx, tx, tenantID, actorID, "assignment.remove", membershipID, roleID); err != nil {
			return nil, translateError(err)
		}
	}
	for _, permissionID := range permissionIDs {
		if err := writeAudit(ctx, tx, tenantID, actorID, "permission.unmap", "permission", permissionID); err != nil {
			return nil, translateError(err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID); err != nil {
		return nil, translateError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID); err != nil {
		return nil, translateError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM roles WHERE id=$1 AND tenant_id=$2`, roleID, tenantID); err != nil {
		return nil, translateError(err)
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "role.delete", "role", roleID); err != nil {
		return nil, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, translateError(err)
	}
	return membershipIDs, nil
}

func (r *Postgres) ListPermissions(ctx context.Context, resource string, limit, offset int) ([]domain.Permission, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,resource,action FROM permissions
		WHERE ($1='' OR resource=$1) ORDER BY resource,action LIMIT $2 OFFSET $3`,
		resource, limit, offset)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	items := make([]domain.Permission, 0)
	for rows.Next() {
		var item domain.Permission
		if err := rows.Scan(&item.ID, &item.Resource, &item.Action); err != nil {
			return nil, translateError(err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Postgres) RolePermissions(ctx context.Context, tenantID, roleID string) ([]domain.Permission, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND tenant_id=$2)`,
		roleID, tenantID).Scan(&exists); err != nil {
		return nil, translateError(err)
	}
	if !exists {
		return nil, domain.ErrNotFound
	}
	rows, err := r.pool.Query(ctx, `
		SELECT p.id,p.resource,p.action FROM role_permissions rp
		JOIN permissions p ON p.id=rp.permission_id
		WHERE rp.role_id=$1 AND rp.tenant_id=$2 ORDER BY p.resource,p.action`,
		roleID, tenantID)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	items := make([]domain.Permission, 0)
	for rows.Next() {
		var item domain.Permission
		if err := rows.Scan(&item.ID, &item.Resource, &item.Action); err != nil {
			return nil, translateError(err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Postgres) ReplaceRolePermissions(ctx context.Context, tenantID, actorID, roleID string, permissionIDs []string) ([]string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, translateError(err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND tenant_id=$2)`, roleID, tenantID).Scan(&exists); err != nil {
		return nil, translateError(err)
	}
	if !exists {
		return nil, domain.ErrNotFound
	}
	for _, id := range permissionIDs {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permissions WHERE id=$1)`, id).Scan(&exists); err != nil {
			return nil, translateError(err)
		}
		if !exists {
			return nil, domain.ErrNotFound
		}
	}
	membershipIDs, err := stringRows(ctx, tx,
		`SELECT DISTINCT tenant_user_id FROM user_roles WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID)
	if err != nil {
		return nil, translateError(err)
	}
	oldIDs, err := stringRows(ctx, tx,
		`SELECT permission_id FROM role_permissions WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID)
	if err != nil {
		return nil, translateError(err)
	}
	old := make(map[string]bool, len(oldIDs))
	for _, id := range oldIDs {
		old[id] = true
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND tenant_id=$2`, roleID, tenantID); err != nil {
		return nil, translateError(err)
	}
	for _, id := range permissionIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id) VALUES($1,$2,$3)`,
			tenantID, roleID, id); err != nil {
			return nil, translateError(err)
		}
	}
	target := make(map[string]bool, len(permissionIDs))
	for _, id := range permissionIDs {
		target[id] = true
	}
	for oldID := range old {
		if !target[oldID] {
			if err := writeAudit(ctx, tx, tenantID, actorID, "permission.unmap", "permission", oldID); err != nil {
				return nil, translateError(err)
			}
		}
	}
	for _, id := range permissionIDs {
		if !old[id] {
			if err := writeAudit(ctx, tx, tenantID, actorID, "permission.map", "permission", id); err != nil {
				return nil, translateError(err)
			}
		}
	}
	if err := writeAudit(ctx, tx, tenantID, actorID, "role.permissions.replace", "role", roleID); err != nil {
		return nil, translateError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, translateError(err)
	}
	return membershipIDs, nil
}

type rowQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func stringRows(ctx context.Context, q rowQueryer, sql string, args ...any) ([]string, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, translateError(err)
	}
	defer rows.Close()
	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, translateError(err)
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func writeAudit(ctx context.Context, tx pgx.Tx, tenantID, actorID, action, targetType, targetID string) error {
	var tenant any
	if tenantID != "" {
		tenant = tenantID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_logs (id,tenant_id,actor_user_id,action,target_type,target_id,details,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,'{}'::jsonb,$7)`,
		uuid.New(), tenant, actorID, action, targetType, targetID, time.Now().UTC())
	return translateError(err)
}

func writeAssignmentAudit(ctx context.Context, tx pgx.Tx, tenantID, actorID, action, membershipID, roleID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_logs (id,tenant_id,actor_user_id,action,target_type,target_id,details,created_at)
		VALUES ($1,$2,$3,$4,'role_assignment',$5,
			jsonb_build_object('membership_id',$6::uuid,'role_id',$5::uuid),$7)`,
		uuid.New(), tenantID, actorID, action, roleID, membershipID, time.Now().UTC())
	return translateError(err)
}
