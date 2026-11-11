CREATE TABLE IF NOT EXISTS platform_admins (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_users_active_tenant_user
    ON tenant_users (tenant_id, user_id)
    WHERE deleted_at IS NULL;

ALTER TABLE audit_logs
    ALTER COLUMN tenant_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::JSONB;
