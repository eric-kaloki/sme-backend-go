-- ==============================================================================
-- Machakos SME Backend - PostgreSQL Database Schema & Initial Seed Data
-- Database Engine: PostgreSQL 12+
-- Description: Recreates the complete schema for users, smes, rbac, audit_logs,
--              and token revocation tables.
-- ==============================================================================

-- 1. Enable Required PostgreSQL Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- 2. USERS TABLE
-- ==============================================================================
CREATE TABLE IF NOT EXISTS users (
    id                      VARCHAR(255) PRIMARY KEY,
    first_name              VARCHAR(100) NOT NULL,
    last_name               VARCHAR(100) NOT NULL,
    email                   VARCHAR(255) UNIQUE NOT NULL,
    username                VARCHAR(100) UNIQUE NOT NULL,
    password                VARCHAR(255) NOT NULL,
    phone                   VARCHAR(50),
    role                    VARCHAR(50) NOT NULL DEFAULT 'OFFICER',
    status                  VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    is_temporary_password   BOOLEAN NOT NULL DEFAULT FALSE,
    reset_token             VARCHAR(255),
    reset_token_expiry      TIMESTAMP WITH TIME ZONE,
    custom_permissions      TEXT,
    last_login              TIMESTAMP WITH TIME ZONE,
    failed_login_count      INT NOT NULL DEFAULT 0,
    locked_until             TIMESTAMP WITH TIME ZONE,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- ==============================================================================
-- 3. SMES TABLE (Encrypted PII fields + Blind Indexes)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS smes (
    id                      VARCHAR(255) PRIMARY KEY,
    business_name           TEXT NOT NULL,
    owner_name              TEXT NOT NULL,
    phone                   TEXT NOT NULL,
    email                   TEXT,
    id_number               TEXT,
    business_name_hash      VARCHAR(255),
    owner_name_hash         VARCHAR(255),
    phone_hash              VARCHAR(255),
    email_hash              VARCHAR(255),
    id_number_hash          VARCHAR(255),
    business_permit_number  VARCHAR(100),
    gender                  VARCHAR(20) NOT NULL,
    category                VARCHAR(100) NOT NULL,
    sub_category            VARCHAR(100),
    pwd                     VARCHAR(10) NOT NULL DEFAULT 'NO',
    sub_county              VARCHAR(100) NOT NULL,
    ward                    VARCHAR(100) NOT NULL,
    market_town             VARCHAR(100),
    business_address        TEXT NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    created_by_id           VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    updated_by_id           VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_smes_status ON smes(status);
CREATE INDEX IF NOT EXISTS idx_smes_category ON smes(category);
CREATE INDEX IF NOT EXISTS idx_smes_sub_county ON smes(sub_county);
CREATE INDEX IF NOT EXISTS idx_smes_ward ON smes(ward);
CREATE INDEX IF NOT EXISTS idx_smes_gender ON smes(gender);
CREATE INDEX IF NOT EXISTS idx_smes_pwd ON smes(pwd);
CREATE INDEX IF NOT EXISTS idx_smes_phone_hash ON smes(phone_hash);
CREATE INDEX IF NOT EXISTS idx_smes_email_hash ON smes(email_hash);
CREATE INDEX IF NOT EXISTS idx_smes_business_name_hash ON smes(business_name_hash);

-- ==============================================================================
-- 4. AUDIT LOGS TABLE
-- ==============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action      VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id   VARCHAR(255),
    old_data    TEXT,
    new_data    TEXT,
    description TEXT,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    user_id     VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    sme_id      VARCHAR(255) REFERENCES smes(id) ON DELETE SET NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_sme_id ON audit_logs(sme_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity_type ON audit_logs(entity_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- ==============================================================================
-- 5. ROLES TABLE (RBAC)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS roles (
    id           VARCHAR(255) PRIMARY KEY,
    name         VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description  TEXT,
    color        VARCHAR(20),
    priority     INT NOT NULL DEFAULT 0,
    is_system    BOOLEAN NOT NULL DEFAULT FALSE,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 6. PERMISSIONS TABLE (RBAC)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id           VARCHAR(255) PRIMARY KEY,
    name         VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description  TEXT,
    category     VARCHAR(50) NOT NULL,
    resource     VARCHAR(50),
    action       VARCHAR(50),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- 7. ROLE_PERMISSIONS TABLE (RBAC Join Table)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    id            VARCHAR(255) PRIMARY KEY,
    role_id       VARCHAR(255) REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(255) REFERENCES permissions(id) ON DELETE CASCADE,
    granted       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked       TIMESTAMP WITH TIME ZONE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_perm_id ON role_permissions(permission_id);

-- ==============================================================================
-- 8. REVOKED TOKENS TABLE (JWT Blacklist)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

-- ==============================================================================
-- 9. INITIAL SEED DATA FOR RBAC ROLES & PERMISSIONS
-- ==============================================================================

-- Remove legacy/deprecated role seeds if re-running
DELETE FROM roles WHERE name IN ('ADMIN', 'OFFICER', 'VIEWER');

-- 4 Official System Roles
INSERT INTO roles (id, name, display_name, description, color, priority, is_system, is_active, created_at, updated_at) VALUES
('role-super-admin', 'SUPER_ADMIN', 'Super Administrator', 'Full system access across all modules, user creation/deletion, audit logs, and permission delegation', '#EF4444', 100, true, true, NOW(), NOW()),
('role-chief-officer', 'CHIEF_OFFICER', 'Chief Officer', 'Executive access for SME management (create/read/update/delete/export), viewing/updating users, and analytics', '#8B5CF6', 90, true, true, NOW(), NOW()),
('role-director', 'DIRECTOR', 'Director', 'Directorate level access for SME management (create/read/update/delete/export), viewing users, and analytics', '#F59E0B', 75, true, true, NOW(), NOW()),
('role-sme-officer', 'SME_OFFICER', 'SME Officer', 'Field officer access for registering SMEs, viewing SME listings, and viewing analytics dashboard', '#10B981', 50, true, true, NOW(), NOW())
ON CONFLICT (name) DO UPDATE SET 
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- System Permissions
INSERT INTO permissions (id, name, display_name, description, category, resource, action, is_active, created_at, updated_at) VALUES
('perm-user-create', 'user:create', 'Create User', 'Ability to register new users (Super Admin only)', 'USER', 'user', 'create', true, NOW(), NOW()),
('perm-user-read', 'user:read', 'Read Users', 'Ability to view user profiles and listings', 'USER', 'user', 'read', true, NOW(), NOW()),
('perm-user-update', 'user:update', 'Update User', 'Ability to edit user details and status', 'USER', 'user', 'update', true, NOW(), NOW()),
('perm-user-delete', 'user:delete', 'Delete User', 'Ability to delete or deactivate users (Super Admin only)', 'USER', 'user', 'delete', true, NOW(), NOW()),

('perm-sme-create', 'sme:create', 'Create SME', 'Ability to register new SME records', 'SME', 'sme', 'create', true, NOW(), NOW()),
('perm-sme-read', 'sme:read', 'Read SMEs', 'Ability to view SME details and lists', 'SME', 'sme', 'read', true, NOW(), NOW()),
('perm-sme-update', 'sme:update', 'Update SME', 'Ability to modify SME record information', 'SME', 'sme', 'update', true, NOW(), NOW()),
('perm-sme-delete', 'sme:delete', 'Delete SME', 'Ability to delete SME records', 'SME', 'sme', 'delete', true, NOW(), NOW()),
('perm-sme-export', 'sme:export', 'Export SMEs', 'Ability to export SME data to Excel/CSV', 'SME', 'sme', 'export', true, NOW(), NOW()),

('perm-analytics-view', 'analytics:view', 'View Analytics', 'Ability to view overview stats and export analytics', 'ANALYTICS', 'analytics', 'view', true, NOW(), NOW()),
('perm-audit-read', 'audit:read', 'View Audit Logs', 'Ability to view system audit logs (Super Admin only)', 'AUDIT', 'audit', 'read', true, NOW(), NOW()),
('perm-perm-delegate', 'permission:delegate', 'Delegate Permissions', 'Ability to assign custom permissions to users', 'RBAC', 'permission', 'delegate', true, NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Reset and Map Permissions for the 4 System Roles
DELETE FROM role_permissions;

-- 1. CHIEF_OFFICER permissions
-- Full SME management + user read/update + analytics (NO user create/delete, NO audit logs)
INSERT INTO role_permissions (id, role_id, permission_id, granted, created_at, updated_at)
SELECT gen_random_uuid()::text, 'role-chief-officer', id, NOW(), NOW(), NOW() FROM permissions
WHERE name IN ('sme:create', 'sme:read', 'sme:update', 'sme:delete', 'sme:export', 'analytics:view', 'user:read', 'user:update')
ON CONFLICT DO NOTHING;

-- 2. DIRECTOR permissions
-- Full SME management + user read + analytics (NO user create/update/delete, NO audit logs)
INSERT INTO role_permissions (id, role_id, permission_id, granted, created_at, updated_at)
SELECT gen_random_uuid()::text, 'role-director', id, NOW(), NOW(), NOW() FROM permissions
WHERE name IN ('sme:create', 'sme:read', 'sme:update', 'sme:delete', 'sme:export', 'analytics:view', 'user:read')
ON CONFLICT DO NOTHING;

-- 3. SME_OFFICER permissions
-- SME create + SME read + analytics dashboard (NO SME update/delete, NO user management, NO audit logs)
INSERT INTO role_permissions (id, role_id, permission_id, granted, created_at, updated_at)
SELECT gen_random_uuid()::text, 'role-sme-officer', id, NOW(), NOW(), NOW() FROM permissions
WHERE name IN ('sme:create', 'sme:read', 'analytics:view')
ON CONFLICT DO NOTHING;

-- Initial Super Admin Seed User
-- Email: admin@county.go.ke | Username: admin | Password: Admin@12345
INSERT INTO users (id, first_name, last_name, email, username, password, role, status, created_at, updated_at)
VALUES (
    'user-super-admin-001',
    'Admin',
    'User',
    'admin@county.go.ke',
    'admin',
    '$argon2id$v=19$m=65536,t=3,p=1$P1HNQfRU6Y/xNCkBGCC5Zw$I3bK92MxtGIA6517nr91I94lbSPhB69eQQMzI+z0hQ4',
    'SUPER_ADMIN',
    'ACTIVE',
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;

