//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"tenant-access-service/internal/application"
	"tenant-access-service/internal/auth"
	"tenant-access-service/internal/config"
)

type testAPI struct {
	router *gin.Engine
	pool   *pgxpool.Pool
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(adminPool.Close)
	if err := adminPool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	schema := "tas_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatalf("create isolated test schema: %v", err)
	}
	poolConfig := adminConfig.Copy()
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		_, _ = adminPool.Exec(ctx, `DROP SCHEMA "`+schema+`" CASCADE`)
		t.Fatalf("create schema-scoped pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := adminPool.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
	})
	for _, path := range []string{
		filepath.Join("..", "..", "migrations", "001_init.sql"),
		filepath.Join("..", "..", "migrations", "002_platform_admin_and_tenant_membership.sql"),
		filepath.Join("..", "..", "seed", "seed.sql"),
	} {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture SQL %s: %v", path, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("execute fixture SQL %s: %v", path, err)
		}
	}

	cfg := config.Config{
		JWTSecret:          "integration-test-secret-must-be-long-enough",
		JWTIssuer:          "tenant-access-service",
		JWTAudience:        "tenant-access-service",
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         24 * time.Hour,
		DBAcquireTime:      5 * time.Second,
		PermissionCacheTTL: time.Minute,
	}
	gin.SetMode(gin.TestMode)
	return &testAPI{router: application.NewServer(pool, cfg).Router(), pool: pool}
}

func TestTenantIsolationAndRequestTenantCannotOverrideToken(t *testing.T) {
	api := newTestAPI(t)
	token := login(t, api, "TENANT_A")

	response := request(t, api, http.MethodGet,
		"/api/v1/roles/77777777-7777-7777-7777-777777777777", token, nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant role status = %d, want 404: %s", response.Code, response.Body.String())
	}
	response = request(t, api, http.MethodGet,
		"/api/v1/tenants/22222222-2222-2222-2222-222222222222", token, nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant tenant status = %d, want 404", response.Code)
	}

	response = request(t, api, http.MethodPost, "/api/v1/users", token, map[string]string{
		"email": "new-user@example.com", "password": "Secret-pass-123", "tenant_id": "22222222-2222-2222-2222-222222222222",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create user status = %d, want 201: %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode user creation response: %v", err)
	}
	var tenantID string
	if err := api.pool.QueryRow(context.Background(), `
		SELECT tenant_id FROM tenant_users WHERE user_id=$1`, envelope.Data.ID).Scan(&tenantID); err != nil {
		t.Fatalf("query created membership: %v", err)
	}
	if tenantID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("created membership tenant = %s; client-supplied tenant overrode token", tenantID)
	}

	response = request(t, api, http.MethodPut,
		"/api/v1/users/33333333-3333-3333-3333-333333333333/roles", token,
		map[string][]string{"role_ids": {"77777777-7777-7777-7777-777777777777"}})
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant role assignment status = %d, want 404", response.Code)
	}
}

func TestAuthenticationAndPermissionCacheInvalidation(t *testing.T) {
	api := newTestAPI(t)
	bad := request(t, api, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "demo@example.com", "password": "wrong-password", "tenant_code": "TENANT_A",
	})
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad password status = %d, want 401", bad.Code)
	}
	token := login(t, api, "TENANT_A")

	allowed := request(t, api, http.MethodGet, "/api/v1/users", token, nil)
	if allowed.Code != http.StatusOK {
		t.Fatalf("seeded admin list users status = %d, want 200: %s", allowed.Code, allowed.Body.String())
	}
	mapping := request(t, api, http.MethodPut,
		"/api/v1/roles/66666666-6666-6666-6666-666666666666/permissions", token,
		map[string][]string{"permission_ids": {}})
	if mapping.Code != http.StatusOK {
		t.Fatalf("remove permissions status = %d, want 200: %s", mapping.Code, mapping.Body.String())
	}
	denied := request(t, api, http.MethodGet, "/api/v1/users", token, nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("after permission update status = %d, want 403: %s", denied.Code, denied.Body.String())
	}

	refreshToken := loginResponseRefresh(t, api, "TENANT_B")
	refresh := request(t, api, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": refreshToken,
	})
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200: %s", refresh.Code, refresh.Body.String())
	}
}

func TestPlatformAdminTenantProvisioningAndManagement(t *testing.T) {
	api := newTestAPI(t)
	if _, err := api.pool.Exec(context.Background(),
		`INSERT INTO platform_admins (user_id) VALUES ($1)`,
		"33333333-3333-3333-3333-333333333333"); err != nil {
		t.Fatalf("promote seeded account to platform administrator: %v", err)
	}

	tenantAdmin := login(t, api, "TENANT_A")
	if got := request(t, api, http.MethodPost, "/api/v1/tenants", tenantAdmin, map[string]string{
		"name": "Unauthorized", "code": "UNAUTHORIZED", "admin_email": "no@example.com", "admin_password": "Secret-pass-123",
	}).Code; got != http.StatusForbidden {
		t.Fatalf("tenant-admin tenant creation status = %d, want 403", got)
	}

	platformToken := loginPlatform(t, api, "demo@example.com", "ChangeMe123!")
	if got := request(t, api, http.MethodGet, "/api/v1/users", platformToken, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("platform token use on tenant endpoint status = %d, want 401", got)
	}
	sharedUser := request(t, api, http.MethodPost, "/api/v1/users", tenantAdmin, map[string]string{
		"email": "shared-user@example.com", "password": "Secret-pass-123",
	})
	if sharedUser.Code != http.StatusCreated {
		t.Fatalf("create shared test user status = %d: %s", sharedUser.Code, sharedUser.Body.String())
	}
	var sharedUserBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sharedUser.Body.Bytes(), &sharedUserBody); err != nil {
		t.Fatalf("decode shared test user: %v", err)
	}
	adminB := login(t, api, "TENANT_B")
	if got := request(t, api, http.MethodPost,
		"/api/v1/users/"+sharedUserBody.Data.ID+"/membership", adminB, nil).Code; got != http.StatusCreated {
		t.Fatalf("create shared test user's second membership status = %d", got)
	}
	if got := request(t, api, http.MethodPatch,
		"/api/v1/platform/users/"+sharedUserBody.Data.ID, tenantAdmin,
		map[string]string{"email": "forbidden@example.com"}).Code; got != http.StatusForbidden {
		t.Fatalf("tenant-admin global identity update status = %d, want 403", got)
	}
	if got := request(t, api, http.MethodPatch,
		"/api/v1/platform/users/"+sharedUserBody.Data.ID, platformToken,
		map[string]string{"email": "shared-updated@example.com", "password": "Updated-pass-123"}).Code; got != http.StatusOK {
		t.Fatalf("platform global identity update status = %d, want 200", got)
	}
	for _, tenantCode := range []string{"TENANT_A", "TENANT_B"} {
		if got := requestLogin(t, api, "shared-updated@example.com", "Updated-pass-123", tenantCode).Code; got != http.StatusOK {
			t.Fatalf("platform-updated identity login for %s status = %d, want 200", tenantCode, got)
		}
	}

	created := request(t, api, http.MethodPost, "/api/v1/tenants", platformToken, map[string]string{
		"name": "Provisioned Tenant", "code": "PROVISIONED",
		"admin_email": "provisioned-admin@example.com", "admin_password": "Tenant-admin-123",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("platform tenant creation status = %d: %s", created.Code, created.Body.String())
	}
	var body struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode provisioned tenant: %v", err)
	}

	newAdmin := loginWithCredentials(t, api, "provisioned-admin@example.com", "Tenant-admin-123", "PROVISIONED")
	if got := request(t, api, http.MethodGet, "/api/v1/users", newAdmin, nil).Code; got != http.StatusOK {
		t.Fatalf("new tenant admin list users status = %d, want 200", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/tenants/"+body.Data.ID, platformToken, nil).Code; got != http.StatusOK {
		t.Fatalf("platform get created tenant status = %d, want 200", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/tenants/"+body.Data.ID, tenantAdmin, nil).Code; got != http.StatusNotFound {
		t.Fatalf("tenant-admin cross-tenant read status = %d, want 404", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/tenants?limit=100", platformToken, nil).Code; got != http.StatusOK {
		t.Fatalf("platform tenant list status = %d, want 200", got)
	}
	if got := request(t, api, http.MethodPatch, "/api/v1/tenants/"+body.Data.ID, platformToken, map[string]string{
		"name": "Provisioned Tenant", "code": "PROVISIONED", "status": "suspended",
	}).Code; got != http.StatusOK {
		t.Fatalf("platform suspend tenant status = %d, want 200", got)
	}
	if got := requestLogin(t, api, "provisioned-admin@example.com", "Tenant-admin-123", "PROVISIONED").Code; got != http.StatusUnauthorized {
		t.Fatalf("login to suspended tenant status = %d, want 401", got)
	}
	if got := request(t, api, http.MethodPatch, "/api/v1/tenants/"+body.Data.ID, platformToken, map[string]string{
		"name": "Provisioned Tenant", "code": "PROVISIONED", "status": "active",
	}).Code; got != http.StatusOK {
		t.Fatalf("platform reactivate tenant status = %d, want 200", got)
	}

	var platformLoginAudits int
	if err := api.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE tenant_id IS NULL AND action='auth.login'`).Scan(&platformLoginAudits); err != nil {
		t.Fatalf("query platform login audit: %v", err)
	}
	if platformLoginAudits != 1 {
		t.Fatalf("platform login audit count = %d, want 1", platformLoginAudits)
	}
}

func TestLoginRefreshAndPrincipalValidationCases(t *testing.T) {
	api := newTestAPI(t)
	if got := requestLogin(t, api, "unknown@example.com", "Wrong-pass-123", "TENANT_A").Code; got != http.StatusUnauthorized {
		t.Fatalf("unknown user login status = %d, want 401", got)
	}

	passwordHash, err := auth.HashPassword("Secret-pass-123")
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	unaffiliatedID := uuid.New()
	if _, err := api.pool.Exec(context.Background(),
		`INSERT INTO users (id,email,password_hash) VALUES ($1,$2,$3)`,
		unaffiliatedID, "unaffiliated@example.com", passwordHash); err != nil {
		t.Fatalf("insert user without membership: %v", err)
	}
	if got := requestLogin(t, api, "unaffiliated@example.com", "Secret-pass-123", "TENANT_A").Code; got != http.StatusUnauthorized {
		t.Fatalf("no-membership login status = %d, want 401", got)
	}
	if _, err := api.pool.Exec(context.Background(),
		`INSERT INTO tenant_users (id,tenant_id,user_id) VALUES ($1,$2,$3)`,
		uuid.New(), "11111111-1111-1111-1111-111111111111", unaffiliatedID); err != nil {
		t.Fatalf("add membership for suspended-tenant test: %v", err)
	}

	if _, err := api.pool.Exec(context.Background(),
		`UPDATE users SET deleted_at=NOW() WHERE email='demo@example.com'`); err != nil {
		t.Fatalf("soft-delete seeded user: %v", err)
	}
	if got := requestLogin(t, api, "demo@example.com", "ChangeMe123!", "TENANT_A").Code; got != http.StatusUnauthorized {
		t.Fatalf("deleted-user login status = %d, want 401", got)
	}

	if _, err := api.pool.Exec(context.Background(),
		`UPDATE tenants SET status='suspended' WHERE code='TENANT_A'`); err != nil {
		t.Fatalf("suspend seeded tenant: %v", err)
	}
	if got := requestLogin(t, api, "unaffiliated@example.com", "Secret-pass-123", "TENANT_A").Code; got != http.StatusUnauthorized {
		t.Fatalf("suspended-tenant login status = %d, want 401", got)
	}

	if _, err := api.pool.Exec(context.Background(),
		`UPDATE users SET deleted_at=NULL WHERE email='demo@example.com'`); err != nil {
		t.Fatalf("restore demo user: %v", err)
	}
	if _, err := api.pool.Exec(context.Background(),
		`UPDATE tenants SET status='active' WHERE code='TENANT_A'`); err != nil {
		t.Fatalf("reactivate demo tenant: %v", err)
	}
	validAccess := login(t, api, "TENANT_A")
	if got := request(t, api, http.MethodGet, "/api/v1/users", validAccess, nil).Code; got != http.StatusOK {
		t.Fatalf("valid access token status = %d, want 200", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users", "", nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users", "not-a-jwt", nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want 401", got)
	}
	refreshToken, err := auth.NewToken(config.Config{
		JWTSecret: "integration-test-secret-must-be-long-enough",
		JWTIssuer: "tenant-access-service", JWTAudience: "tenant-access-service",
	}, "33333333-3333-3333-3333-333333333333",
		"11111111-1111-1111-1111-111111111111",
		"44444444-4444-4444-4444-444444444444",
		"refresh", time.Hour)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users", refreshToken, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("refresh token on protected endpoint status = %d, want 401", got)
	}
	if got := request(t, api, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": "invalid",
	}).Code; got != http.StatusUnauthorized {
		t.Fatalf("invalid refresh status = %d, want 401", got)
	}
	refreshForSuspendedTenant := loginResponseRefresh(t, api, "TENANT_B")
	if _, err := api.pool.Exec(context.Background(),
		`UPDATE tenants SET status='suspended' WHERE code='TENANT_B'`); err != nil {
		t.Fatalf("suspend tenant B: %v", err)
	}
	if got := request(t, api, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{
		"refresh_token": refreshForSuspendedTenant,
	}).Code; got != http.StatusUnauthorized {
		t.Fatalf("refresh for suspended tenant status = %d, want 401", got)
	}
}

func TestMembershipUserRoleAndSoftDeleteFlows(t *testing.T) {
	api := newTestAPI(t)
	adminA := login(t, api, "TENANT_A")
	adminB := login(t, api, "TENANT_B")

	created := request(t, api, http.MethodPost, "/api/v1/users", adminA, map[string]string{
		"email": "operator@example.com", "password": "Secret-pass-123",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create user status = %d: %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatalf("decode created user: %v", err)
	}
	userID := createdBody.Data.ID

	var userReadID string
	if err := api.pool.QueryRow(context.Background(),
		`SELECT id FROM permissions WHERE resource='user' AND action='read'`).Scan(&userReadID); err != nil {
		t.Fatalf("query user:read permission: %v", err)
	}
	roleOne := createRole(t, api, adminA, "reader")
	roleTwo := createRole(t, api, adminA, "role-reader")
	for roleID, permissionIDs := range map[string][]string{
		roleOne: {userReadID},
		roleTwo: {},
	} {
		if roleID == roleTwo {
			var roleReadID string
			if err := api.pool.QueryRow(context.Background(),
				`SELECT id FROM permissions WHERE resource='role' AND action='read'`).Scan(&roleReadID); err != nil {
				t.Fatalf("query role:read permission: %v", err)
			}
			permissionIDs = []string{roleReadID}
		}
		result := request(t, api, http.MethodPut, "/api/v1/roles/"+roleID+"/permissions", adminA,
			map[string][]string{"permission_ids": permissionIDs})
		if result.Code != http.StatusOK {
			t.Fatalf("map role permissions status = %d: %s", result.Code, result.Body.String())
		}
	}

	assigned := request(t, api, http.MethodPut, "/api/v1/users/"+userID+"/roles", adminA,
		map[string][]string{"role_ids": {roleOne, roleTwo}})
	if assigned.Code != http.StatusOK {
		t.Fatalf("assign roles status = %d: %s", assigned.Code, assigned.Body.String())
	}
	operatorToken := loginWithCredentials(t, api, "operator@example.com", "Secret-pass-123", "TENANT_A")
	if got := request(t, api, http.MethodGet, "/api/v1/users", operatorToken, nil).Code; got != http.StatusOK {
		t.Fatalf("user:read via first role status = %d, want 200", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/roles", operatorToken, nil).Code; got != http.StatusOK {
		t.Fatalf("role:read via second role status = %d, want 200", got)
	}

	update := request(t, api, http.MethodPatch, "/api/v1/users/"+userID, adminA, map[string]string{
		"email": "operator-updated@example.com", "password": "Updated-pass-123",
	})
	if update.Code != http.StatusOK {
		t.Fatalf("update user status = %d: %s", update.Code, update.Body.String())
	}
	if got := requestLogin(t, api, "operator-updated@example.com", "Updated-pass-123", "TENANT_A").Code; got != http.StatusOK {
		t.Fatalf("login after user update status = %d", got)
	}

	membership := request(t, api, http.MethodPost, "/api/v1/users/"+userID+"/membership", adminB, nil)
	if membership.Code != http.StatusCreated {
		t.Fatalf("add second tenant membership status = %d: %s", membership.Code, membership.Body.String())
	}
	duplicate := request(t, api, http.MethodPost, "/api/v1/users/"+userID+"/membership", adminB, nil)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate membership status = %d, want 409", duplicate.Code)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users?email=operator@", adminB, nil).Code; got != http.StatusOK {
		t.Fatalf("list user in second tenant status = %d", got)
	}
	if got := request(t, api, http.MethodPatch, "/api/v1/users/"+userID, adminA,
		map[string]string{"email": "shared@example.com"}).Code; got != http.StatusConflict {
		t.Fatalf("shared identity update status = %d, want 409", got)
	}
	if got := requestLogin(t, api, "operator-updated@example.com", "Updated-pass-123", "TENANT_B").Code; got != http.StatusOK {
		t.Fatalf("shared identity should remain unchanged in tenant B, status = %d", got)
	}

	remove := request(t, api, http.MethodDelete, "/api/v1/users/"+userID+"/roles", adminA,
		map[string][]string{"role_ids": {roleOne}})
	if remove.Code != http.StatusOK {
		t.Fatalf("remove role assignment status = %d: %s", remove.Code, remove.Body.String())
	}
	var membershipID string
	if err := api.pool.QueryRow(context.Background(),
		`SELECT id FROM tenant_users WHERE user_id=$1 AND tenant_id=$2`,
		userID, "11111111-1111-1111-1111-111111111111").Scan(&membershipID); err != nil {
		t.Fatalf("query operator membership: %v", err)
	}
	var assignmentAuditCount int
	if err := api.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_logs
		WHERE action='assignment.remove' AND target_type='role_assignment'
			AND target_id=$1 AND details->>'membership_id'=$2`,
		roleOne, membershipID).Scan(&assignmentAuditCount); err != nil {
		t.Fatalf("query role assignment audit: %v", err)
	}
	if assignmentAuditCount != 1 {
		t.Fatalf("assignment removal audit count = %d, want 1", assignmentAuditCount)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users", operatorToken, nil).Code; got != http.StatusForbidden {
		t.Fatalf("cache invalidation after role removal status = %d, want 403", got)
	}
	if got := request(t, api, http.MethodGet, "/api/v1/roles", operatorToken, nil).Code; got != http.StatusOK {
		t.Fatalf("selected role removal should preserve other role status = %d, want 200", got)
	}

	deleted := request(t, api, http.MethodDelete, "/api/v1/users/"+userID, adminA, nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("soft-delete user status = %d: %s", deleted.Code, deleted.Body.String())
	}
	var deletedAt *time.Time
	if err := api.pool.QueryRow(context.Background(), `SELECT deleted_at FROM tenant_users WHERE user_id=$1 AND tenant_id=$2`,
		userID, "11111111-1111-1111-1111-111111111111").Scan(&deletedAt); err != nil {
		t.Fatalf("query soft-deleted tenant membership: %v", err)
	}
	if deletedAt == nil {
		t.Fatal("expected soft-deleted tenant membership to have deleted_at")
	}
	if got := requestLogin(t, api, "operator-updated@example.com", "Updated-pass-123", "TENANT_A").Code; got != http.StatusUnauthorized {
		t.Fatalf("deleted tenant membership login status = %d, want 401", got)
	}
	if got := requestLogin(t, api, "operator-updated@example.com", "Updated-pass-123", "TENANT_B").Code; got != http.StatusOK {
		t.Fatalf("deactivation in tenant A should preserve tenant B login, status = %d", got)
	}
	reactivated := request(t, api, http.MethodPost, "/api/v1/users/"+userID+"/membership", adminA, nil)
	if reactivated.Code != http.StatusCreated {
		t.Fatalf("reactivate tenant membership status = %d: %s", reactivated.Code, reactivated.Body.String())
	}
	reactivatedToken := loginWithCredentials(t, api, "operator-updated@example.com", "Updated-pass-123", "TENANT_A")
	if got := request(t, api, http.MethodGet, "/api/v1/users", reactivatedToken, nil).Code; got != http.StatusForbidden {
		t.Fatalf("reactivated membership must not regain roles, status = %d, want 403", got)
	}

	var auditCount int
	if err := api.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs
		WHERE target_id=$1
			OR target_id IN (SELECT id FROM tenant_users WHERE user_id=$2)
			OR details->>'membership_id' IN (SELECT id::text FROM tenant_users WHERE user_id=$2)`,
		userID, userID).Scan(&auditCount); err != nil {
		t.Fatalf("query user audit records: %v", err)
	}
	if auditCount < 3 {
		t.Fatalf("user audit count = %d, want at least 3 changes", auditCount)
	}

	deletedRole := request(t, api, http.MethodDelete, "/api/v1/roles/"+roleTwo, adminA, nil)
	if deletedRole.Code != http.StatusOK {
		t.Fatalf("delete role with dependent data status = %d: %s", deletedRole.Code, deletedRole.Body.String())
	}
}

func TestSuspendedTenantCanOnlyBeReactivatedWithExistingAdminToken(t *testing.T) {
	api := newTestAPI(t)
	token := login(t, api, "TENANT_A")
	suspend := request(t, api, http.MethodPatch,
		"/api/v1/tenants/11111111-1111-1111-1111-111111111111", token,
		map[string]string{"name": "Demo Tenant A", "code": "TENANT_A", "status": "suspended"})
	if suspend.Code != http.StatusOK {
		t.Fatalf("suspend tenant status = %d: %s", suspend.Code, suspend.Body.String())
	}
	if got := request(t, api, http.MethodGet, "/api/v1/users", token, nil).Code; got != http.StatusForbidden {
		t.Fatalf("suspended tenant user list status = %d, want 403", got)
	}
	reactivate := request(t, api, http.MethodPatch,
		"/api/v1/tenants/11111111-1111-1111-1111-111111111111", token,
		map[string]string{"name": "Demo Tenant A", "code": "TENANT_A", "status": "active"})
	if reactivate.Code != http.StatusOK {
		t.Fatalf("reactivate tenant status = %d: %s", reactivate.Code, reactivate.Body.String())
	}
}

func TestAuditFailureRollsBackUserCreation(t *testing.T) {
	api := newTestAPI(t)
	admin := login(t, api, "TENANT_A")
	if _, err := api.pool.Exec(context.Background(), `DROP TABLE audit_logs`); err != nil {
		t.Fatalf("drop audit table for failure injection: %v", err)
	}
	result := request(t, api, http.MethodPost, "/api/v1/users", admin, map[string]string{
		"email": "rollback@example.com", "password": "Secret-pass-123",
	})
	if result.Code != http.StatusInternalServerError {
		t.Fatalf("create without audit table status = %d, want 500", result.Code)
	}
	var count int
	if err := api.pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE lower(email)='rollback@example.com'`).Scan(&count); err != nil {
		t.Fatalf("check rollback result: %v", err)
	}
	if count != 0 {
		t.Fatalf("user insert was not rolled back; count = %d", count)
	}
}

func TestAuditFailureRollsBackTenantProvisioning(t *testing.T) {
	api := newTestAPI(t)
	if _, err := api.pool.Exec(context.Background(),
		`INSERT INTO platform_admins (user_id) VALUES ($1)`,
		"33333333-3333-3333-3333-333333333333"); err != nil {
		t.Fatalf("promote seeded account to platform administrator: %v", err)
	}
	platformToken := loginPlatform(t, api, "demo@example.com", "ChangeMe123!")
	if _, err := api.pool.Exec(context.Background(), `DROP TABLE audit_logs`); err != nil {
		t.Fatalf("drop audit table for failure injection: %v", err)
	}
	result := request(t, api, http.MethodPost, "/api/v1/tenants", platformToken, map[string]string{
		"name": "Rollback Tenant", "code": "ROLLBACK",
		"admin_email": "rollback-admin@example.com", "admin_password": "Tenant-admin-123",
	})
	if result.Code != http.StatusInternalServerError {
		t.Fatalf("tenant creation without audit table status = %d, want 500", result.Code)
	}
	var tenantCount, userCount int
	if err := api.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tenants WHERE code='ROLLBACK'`).Scan(&tenantCount); err != nil {
		t.Fatalf("check tenant transaction rollback: %v", err)
	}
	if err := api.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE lower(email)='rollback-admin@example.com'`).Scan(&userCount); err != nil {
		t.Fatalf("check initial admin transaction rollback: %v", err)
	}
	if tenantCount != 0 || userCount != 0 {
		t.Fatalf("tenant provisioning was not atomic: tenant count=%d, admin count=%d", tenantCount, userCount)
	}
}

func createRole(t *testing.T, api *testAPI, token, name string) string {
	t.Helper()
	result := request(t, api, http.MethodPost, "/api/v1/roles", token, map[string]string{"name": name})
	if result.Code != http.StatusCreated {
		t.Fatalf("create role status = %d: %s", result.Code, result.Body.String())
	}
	var body struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode role response: %v", err)
	}
	return body.Data.ID
}

func login(t *testing.T, api *testAPI, tenantCode string) string {
	t.Helper()
	response := requestLogin(t, api, "demo@example.com", "ChangeMe123!", tenantCode)
	if response.Code != http.StatusOK {
		t.Fatalf("login %s status = %d: %s", tenantCode, response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if body.Data.AccessToken == "" {
		t.Fatal("login response has no access token")
	}
	return body.Data.AccessToken
}

func loginResponseRefresh(t *testing.T, api *testAPI, tenantCode string) string {
	t.Helper()
	response := requestLogin(t, api, "demo@example.com", "ChangeMe123!", tenantCode)
	if response.Code != http.StatusOK {
		t.Fatalf("login %s status = %d: %s", tenantCode, response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return body.Data.RefreshToken
}

func loginPlatform(t *testing.T, api *testAPI, email, password string) string {
	t.Helper()
	response := request(t, api, http.MethodPost, "/api/v1/auth/platform-login", "", map[string]string{
		"email": email, "password": password,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("platform login status = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode platform login response: %v", err)
	}
	if body.Data.AccessToken == "" {
		t.Fatal("platform login response has no access token")
	}
	return body.Data.AccessToken
}

func loginWithCredentials(t *testing.T, api *testAPI, email, password, tenantCode string) string {
	t.Helper()
	response := requestLogin(t, api, email, password, tenantCode)
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return body.Data.AccessToken
}

func requestLogin(t *testing.T, api *testAPI, email, password, tenantCode string) *httptest.ResponseRecorder {
	t.Helper()
	return request(t, api, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": email, "password": password, "tenant_code": tenantCode,
	})
}

func request(t *testing.T, api *testAPI, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request body: %v", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, requestBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	api.router.ServeHTTP(recorder, req)
	return recorder
}
