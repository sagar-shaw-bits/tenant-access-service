INSERT INTO tenants (id, name, code, status)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'Demo Tenant A', 'TENANT_A', 'active'),
    ('22222222-2222-2222-2222-222222222222', 'Demo Tenant B', 'TENANT_B', 'active')
ON CONFLICT (code) DO NOTHING;

INSERT INTO permissions (id, resource, action)
VALUES
    ('10000000-0000-0000-0000-000000000001', 'tenant', 'read'),
    ('10000000-0000-0000-0000-000000000002', 'tenant', 'update'),
    ('20000000-0000-0000-0000-000000000001', 'user', 'create'),
    ('20000000-0000-0000-0000-000000000002', 'user', 'read'),
    ('20000000-0000-0000-0000-000000000003', 'user', 'update'),
    ('20000000-0000-0000-0000-000000000004', 'user', 'delete'),
    ('30000000-0000-0000-0000-000000000001', 'membership', 'create'),
    ('40000000-0000-0000-0000-000000000001', 'role', 'create'),
    ('40000000-0000-0000-0000-000000000002', 'role', 'read'),
    ('40000000-0000-0000-0000-000000000003', 'role', 'update'),
    ('40000000-0000-0000-0000-000000000004', 'role', 'delete'),
    ('50000000-0000-0000-0000-000000000001', 'permission', 'read'),
    ('50000000-0000-0000-0000-000000000002', 'permission', 'map'),
    ('60000000-0000-0000-0000-000000000001', 'assignment', 'manage')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO users (id, email, password_hash)
VALUES ('33333333-3333-3333-3333-333333333333', 'demo@example.com',
        '$2a$10$IbMZwYN6352E/k.eVfB9.epKqTWFKKomnYvO7Dz0/pHUFaHiEyy4C')
ON CONFLICT ((lower(email))) DO NOTHING;

INSERT INTO tenant_users (id, tenant_id, user_id)
VALUES
    ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333'),
    ('55555555-5555-5555-5555-555555555555', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
ON CONFLICT (tenant_id, user_id) DO NOTHING;

INSERT INTO roles (id, tenant_id, name)
VALUES
    ('66666666-6666-6666-6666-666666666666', '11111111-1111-1111-1111-111111111111', 'tenant-admin'),
    ('77777777-7777-7777-7777-777777777777', '22222222-2222-2222-2222-222222222222', 'tenant-admin')
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'tenant-admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO user_roles (tenant_id, tenant_user_id, role_id)
SELECT tu.tenant_id, tu.id, r.id
FROM tenant_users tu
JOIN roles r ON r.tenant_id = tu.tenant_id AND r.name = 'tenant-admin'
WHERE tu.user_id = '33333333-3333-3333-3333-333333333333'
ON CONFLICT (tenant_user_id, role_id) DO NOTHING;
