# Tenant Access Service

Go/Gin/PostgreSQL modular monolith for tenant-scoped users and RBAC.

## Requirements

- Go 1.25 or later
- Docker Desktop with Docker Compose, or PostgreSQL 16
- `psql` only if you prefer running SQL migrations from the host

## Start with Docker Compose (PowerShell)

Run these commands from the repository root:

```powershell
docker compose up -d --build
docker compose ps
```

Apply the schema and local demonstration seed:

```powershell
$db = (docker compose ps -q postgres).Trim()
docker cp .\migrations\001_init.sql "${db}:/tmp/001_init.sql"
docker compose exec -T postgres psql -U postgres -d tenant_access_service -v ON_ERROR_STOP=1 -f /tmp/001_init.sql
docker cp .\migrations\002_platform_admin_and_tenant_membership.sql "${db}:/tmp/002_platform_admin_and_tenant_membership.sql"
docker compose exec -T postgres psql -U postgres -d tenant_access_service -v ON_ERROR_STOP=1 -f /tmp/002_platform_admin_and_tenant_membership.sql
docker cp .\seed\seed.sql "${db}:/tmp/seed.sql"
docker compose exec -T postgres psql -U postgres -d tenant_access_service -v ON_ERROR_STOP=1 -f /tmp/seed.sql
```

Verify the API and seeded data:

```powershell
Invoke-RestMethod http://localhost:8080/healthz
docker compose exec -T postgres psql -U postgres -d tenant_access_service -c "SELECT code,status FROM tenants ORDER BY code"
```

The local demo account is `demo@example.com` / `ChangeMe123!`, with memberships in `TENANT_A` and `TENANT_B`. It receives a tenant-admin role in each seeded tenant. This account is for local demonstration only; change or remove it before using any non-local deployment.

Platform administration is separate from tenant-admin RBAC and is not granted by the demo seed. To bootstrap a platform admin, create a dedicated account through the normal tenant user-management flow, then grant platform-admin access through a controlled database operation:

```sql
INSERT INTO platform_admins (user_id)
SELECT id FROM users WHERE lower(email) = lower('platform-admin@example.com')
ON CONFLICT (user_id) DO NOTHING;
```

Only operators with database administration access should grant this capability. Platform admins authenticate through `POST /api/v1/auth/platform-login`. They can create tenants and their initial tenant admin atomically, and manage/list tenants across the platform. Tenant admins remain restricted to their own tenant.

## Local API process

For a local Go process connecting to the Compose database, set the environment in PowerShell:

```powershell
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5432"
$env:DB_USER = "postgres"
$env:DB_PASSWORD = "postgres"
$env:DB_NAME = "tenant_access_service"
$env:DB_SSLMODE = "disable"
$env:JWT_SECRET = "local-development-secret-change-this"
go run ./cmd/api
```

The program reads environment variables; it does not automatically load `.env`. `.env.example` lists supported settings. In Compose, the API is configured to connect to the `postgres` service.

## Migrations

Apply the ordered up migrations, then the seed SQL as shown above. To roll back, first execute `migrations/002_platform_admin_and_tenant_membership.down.sql`, then `migrations/001_init.down.sql`. The down migrations remove application data; only use them when that is intended.

The API does not automatically migrate the database at startup. This avoids applying destructive or unreviewed schema changes as a side effect of starting the service.

## API and Postman

- OpenAPI 3 specification: [`docs/swagger/openapi.yaml`](docs/swagger/openapi.yaml)
- ER diagram: [`docs/er-diagram.md`](docs/er-diagram.md)
- Design decisions: [`docs/design.md`](docs/design.md)

Base URL: `http://localhost:8080/api/v1`. Login at `POST /auth/login` with JSON fields `email`, `password`, and `tenant_code`; use the returned `access_token` as a Bearer token for protected endpoints. The refresh token is stateless and cannot be individually revoked in this version.

To try the API in Postman, import `docs/swagger/openapi.yaml`, set the server to `http://localhost:8080/api/v1`, run the login request, then set the returned access token as a Bearer token for protected requests.

Tenant provisioning is restricted to platform admins. Creating a tenant requires `name`, `code`, `admin_email`, and `admin_password`; the tenant, first tenant-admin user/membership, tenant-admin role, permissions, and audit records are committed atomically. Tenant admins can read/update only the tenant in their access token. Platform admins can manage all tenants.

`POST /api/v1/auth/platform-login` accepts `email` and `password`, and returns a platform-scoped access token without tenant claims. Do not use this token for tenant user/role endpoints. The tenant `DELETE /users/{id}` operation soft-deactivates the user's membership in the authenticated tenant; a shared user identity and memberships in other tenants remain active.

Email/password changes affect the global login identity. Tenant admins can make those changes only while the user has one active tenant membership; shared identities must be changed through `PATCH /api/v1/platform/users/{id}` with a platform token. Reactivating a deactivated membership does not restore its former role assignments.

### Postman end-to-end feature test

Start the API, apply both up migrations, and load the seed data using the Docker Compose steps above. Confirm `http://localhost:8080/healthz` returns HTTP 200. First verify the literal demo login below; for the remaining walkthrough, import `docs/swagger/openapi.yaml` into Postman and create an environment with these variables:

**Quick copy-paste login (no Postman environment required):**

- Method: `POST`
- URL: `http://localhost:8080/api/v1/auth/login`
- Authorization tab: **No Auth**
- Header: `Content-Type: application/json`
- Body tab: **raw** → **JSON**:

  ```json
  {
    "email": "demo@example.com",
    "password": "ChangeMe123!",
    "tenant_code": "TENANT_A"
  }
  ```

Click **Send**. With the Compose database, both migrations, and seed data applied, expect HTTP 200 with `data.access_token` and `data.refresh_token`. For Tenant B, repeat with `"tenant_code": "TENANT_B"`. This is a tenant login; platform login is a different endpoint and requires an account explicitly granted platform-admin status. If this exact request returns 401, follow the database setup above and verify the seeded account and active membership before changing the request.

For protected requests, select **Authorization → Bearer Token** and paste the `data.access_token` value from the successful login. Do not include quotation marks or the word `Bearer` in the token field; Postman adds the scheme. Use the tenant A or B token corresponding to the request.

| Variable | Value |
|---|---|
| `baseUrl` | `http://localhost:8080/api/v1` |
| `tenantA` / `tenantB` | `TENANT_A` / `TENANT_B` |
| `tenantAId` / `tenantBId` | `11111111-1111-1111-1111-111111111111` / `22222222-2222-2222-2222-222222222222` |
| `demoEmail` / `demoPassword` | `demo@example.com` / `ChangeMe123!` |
| `testUserEmail` | A new, unique email for this run |
| `testUserPassword` | `Test-user-123!` |
| `platformAdminEmail` | A new, unique email for this run |
| `platformAdminPassword` | `Platform-admin-123!` |
| `newTenantCode` | A new, unique tenant code for this run |
| `newTenantAdminEmail` | A new, unique email for this run |
| `newTenantAdminPassword` | `Tenant-admin-123!` |

Use the imported API's bearer authentication or add `Authorization: Bearer {{tenantAToken}}` to tenant-A requests. In each login request's **Scripts → Post-response** tab, save tokens like this:

```javascript
const body = pm.response.json();
pm.test("login succeeded", () => pm.response.to.have.status(200));
pm.environment.set("accessToken", body.data.access_token);
pm.environment.set("tenantAToken", body.data.access_token);
if (body.data.refresh_token) {
  pm.environment.set("refreshToken", body.data.refresh_token);
}
```

Also save the access token under a separate variable for each identity: `tenantAToken`, `tenantBToken`, `platformToken`, or `newTenantAdminToken`. The response envelope puts resource IDs under `data.id`. Use **Body → raw → JSON** and `Content-Type: application/json` for JSON request bodies.

In Postman, set each protected request's **Authorization** tab to **Bearer Token** and enter the matching variable, for example `{{tenantAToken}}`. In a login post-response script, add the matching save line, for example `pm.environment.set("tenantAToken", body.data.access_token);`; use `tenantBToken`, `platformToken`, or `newTenantAdminToken` for the other login requests.

Run the following requests in order. Replace `<...>` with actual UUIDs from previous responses; do not include the angle brackets.

1. **Authentication and tenant isolation**
   - Send the exact literal login request above → expect 200. Save `tenantAToken` and `refreshToken` with the post-response script.
   - `POST {{baseUrl}}/auth/refresh` with `{"refresh_token":"{{refreshToken}}"}` → expect 200; save the new access token as both `accessToken` and `tenantAToken`.
   - `GET {{baseUrl}}/tenants` with `tenantAToken` → only Tenant A. `GET {{baseUrl}}/tenants/{{tenantBId}}` → 404.
   - `GET {{baseUrl}}/users` with no token or an invalid token → 401. `GET {{baseUrl}}/users?limit=0` → 400. Login with an incorrect password → 401.

2. **User create, list, read, and update**
   - `POST {{baseUrl}}/users` with `{"email":"{{testUserEmail}}","password":"{{testUserPassword}}"}` and `tenantAToken` → 201. Save `data.id` as `testUserId`.
   - `GET {{baseUrl}}/users?limit=10&offset=0&email={{testUserEmail}}` and `GET {{baseUrl}}/users/{{testUserId}}` → 200.
   - `PATCH {{baseUrl}}/users/{{testUserId}}` with `{"email":"{{testUserEmail}}","password":"{{testUserPassword}}"}` → 200.
   - Try creating a user with an invalid email or password shorter than eight characters → 400.

3. **Roles, permissions, and RBAC**
   - `GET {{baseUrl}}/permissions?resource=user` and `GET {{baseUrl}}/permissions?resource=role` → 200. Record the permission UUIDs for `user:read` and `role:read`.
   - `POST {{baseUrl}}/roles` with `{"name":"postman-reader"}` → 201; save `data.id` as `readerRoleId`. Create a second role named `postman-role-reader`; save its ID as `roleReaderRoleId`.
   - `PUT {{baseUrl}}/roles/{{readerRoleId}}/permissions` with `{"permission_ids":["<user:read permission UUID>"]}` → 200. Map `role:read` to `roleReaderRoleId` in the same way.
   - `GET {{baseUrl}}/roles/{{readerRoleId}}/permissions`, `GET {{baseUrl}}/roles?limit=20&offset=0&name=postman`, and `GET {{baseUrl}}/roles/{{readerRoleId}}` → 200.
   - `PATCH {{baseUrl}}/roles/{{readerRoleId}}` with `{"name":"postman-reader-renamed"}` → 200.
   - `PUT {{baseUrl}}/users/{{testUserId}}/roles` with `{"role_ids":["<readerRoleId>","<roleReaderRoleId>"]}` → 200.
   - Log in as the test user in Tenant A. With that user's token, `GET /users` and `GET /roles` should each return 200.
   - `DELETE {{baseUrl}}/users/{{testUserId}}/roles` with `{"role_ids":["<readerRoleId>"]}` → 200. The test user's next `GET /users` should return 403, while `GET /roles` remains 200 because the other role is still assigned.
   - Try assigning the seeded Tenant B role `77777777-7777-7777-7777-777777777777` to this Tenant A user → 404.

4. **Create and promote a platform administrator**
   - With `tenantAToken`, create a separate account using `POST {{baseUrl}}/users` and `{"email":"{{platformAdminEmail}}","password":"{{platformAdminPassword}}"}`.
   - Grant it platform-admin status using this controlled local database operation; replace the example email with the environment value:

     ```powershell
     docker compose exec -T postgres psql -U postgres -d tenant_access_service -v ON_ERROR_STOP=1 -c "INSERT INTO platform_admins (user_id) SELECT id FROM users WHERE lower(email)=lower('platform-admin@example.com') ON CONFLICT (user_id) DO NOTHING"
     ```

   - `POST {{baseUrl}}/auth/platform-login` with the platform-admin email/password → 200. Save the returned access token as `platformToken`.

5. **Multiple tenant memberships and shared identities**
   - `POST {{baseUrl}}/auth/login` using `tenantB` and the demo credentials; save `tenantBToken`.
   - `POST {{baseUrl}}/users/{{testUserId}}/membership` with `tenantBToken` and no body → 201. Repeat → 409.
   - With `tenantAToken`, `PATCH {{baseUrl}}/users/{{testUserId}}` attempting to change its email or password → 409 because the identity has active memberships in two tenants.
   - `PATCH {{baseUrl}}/platform/users/{{testUserId}}` with `platformToken` and a JSON body containing a new `email` and `password` → 200. Update `testUserEmail` and `testUserPassword` in the Postman environment to those new values, then confirm that login succeeds in both tenants.

6. **Membership deactivation and reactivation**
   - `DELETE {{baseUrl}}/users/{{testUserId}}` with the Tenant A admin token → 200. The test user should now get 401 logging into Tenant A but still log in successfully to Tenant B.
   - `POST {{baseUrl}}/users/{{testUserId}}/membership` with the Tenant A admin token → 201. After the test user logs in again to Tenant A, `GET /users` should return 403 until roles are reassigned; reactivation does not restore former roles.
   - `DELETE {{baseUrl}}/users/{{testUserId}}/roles` with `{"role_ids":["<roleReaderRoleId>"]}` → 200. Then `DELETE {{baseUrl}}/roles/{{readerRoleId}}` and `DELETE {{baseUrl}}/roles/{{roleReaderRoleId}}` → 200.

7. **Tenant provisioning and platform access**
   - `GET {{baseUrl}}/tenants?limit=100&offset=0` with `platformToken` → 200 and a paginated list.
   - `POST {{baseUrl}}/tenants` with `{"name":"Postman Tenant","code":"{{newTenantCode}}","admin_email":"{{newTenantAdminEmail}}","admin_password":"{{newTenantAdminPassword}}"}` → 201. Save `data.id` as `newTenantId`.
   - Log in with the new tenant admin credentials and `newTenantCode`; `GET /users` should return 200, confirming its initial tenant-admin role and permissions were provisioned.
   - With `platformToken`, `GET /tenants/{{newTenantId}}` → 200. `PATCH /tenants/{{newTenantId}}` with `{"name":"Postman Tenant","code":"{{newTenantCode}}","status":"suspended"}` → 200; login to that tenant should return 401. Patch status back to `active`.
   - With `tenantAToken`, `GET /tenants/{{newTenantId}}` → 404 and `POST /tenants` → 403. With `platformToken`, `GET /users` → 401 (platform tokens are not tenant tokens).

8. **Audit records**
   - There is no audit-log API endpoint. Inspect recent login and change events in PostgreSQL:

     ```powershell
     docker compose exec -T postgres psql -U postgres -d tenant_access_service -c "SELECT action,target_type,target_id,details,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 30"
     ```

   - Assignment audit details should identify `membership_id` and `role_id`. Platform login events have a null `tenant_id`.

The database persists between runs. Use unique test emails and tenant codes each time; duplicate accounts, roles, and tenant codes can return 409. If a request differs from the expected status, inspect its JSON error envelope and `docker compose logs api`. Automated integration tests covering isolation, RBAC, membership, provisioning, and audit rollback are in `tests/integration/api_test.go`.

## Tests

```powershell
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
```

PostgreSQL-backed integration tests use a temporary schema inside the database URL supplied through `TEST_DATABASE_URL` and drop that schema when finished:

```powershell
$env:TEST_DATABASE_URL = "postgres://postgres:postgres@localhost:5432/tenant_access_service?sslmode=disable"
go test -tags=integration ./tests/integration/...
```

Run integration tests only against a database where the test user is allowed to create and drop schemas. They do not reset or drop the database itself.
