ALTER TABLE audit_logs DROP COLUMN IF EXISTS details;
DELETE FROM audit_logs WHERE tenant_id IS NULL;
ALTER TABLE audit_logs ALTER COLUMN tenant_id SET NOT NULL;
DROP INDEX IF EXISTS idx_tenant_users_active_tenant_user;
ALTER TABLE tenant_users DROP COLUMN IF EXISTS deleted_at;
DROP TABLE IF EXISTS platform_admins;
