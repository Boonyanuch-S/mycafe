-- 1. Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Index สำหรับ login
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- Admin user (password: admin123)
INSERT INTO users (username, email, password_hash, email_verified)
VALUES (
    'aomsin',
    'admin@bookstore.com',
    '$2a$12$3BPX09K0yJaNPqOu0d.HMeHz4W7bC8rU3CMufkR2yQ9RHX4RUhA9y',
    true
);

-- Editor user (password: editor123)
INSERT INTO users (username, email, password_hash, email_verified)
VALUES (
    'noodle',
    'editor@bookstore.com',
    '$2a$12$1nPcjMzNeowC8RxIUggxruqvUVFEhQawl2bEu4dRNZ4RILQD7wX9q',
    true
);

-- Regular user (password: user123)
INSERT INTO users (username, email, password_hash, email_verified)
VALUES (
    'sasichai',
    'user@bookstore.com',
    '$2a$12$BMF2D4vNPNXHQZ6IGRKAaePuzhhAsxHVRexuoHt2./cwVQfV36aPG',
    true
);

-- 2. Roles Table

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false,  -- role ที่ลบไม่ได้ (admin, user)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_roles_name ON roles(name);

-- 3. User-Role Assignment

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER REFERENCES users(id),  -- ใครเป็นคนมอบหมาย
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- Seed Roles
INSERT INTO roles (name, description, is_system) VALUES
('admin', 'Administrator with full system access', true),
('editor', 'Can create and edit content', false),
('viewer', 'Read-only access', false),
('user', 'Default role for new users', true);

-- Assign Roles to Users
-- admin user >> admin role
INSERT INTO user_roles (user_id, role_id)
SELECT
    (SELECT id FROM users WHERE username = 'aomsin'),
    (SELECT id FROM roles WHERE name = 'admin');

-- editor user >> editor role
INSERT INTO user_roles (user_id, role_id)
SELECT
    (SELECT id FROM users WHERE username = 'noodle'),
    (SELECT id FROM roles WHERE name = 'editor');

-- regular user >> user role
INSERT INTO user_roles (user_id, role_id)
SELECT
    (SELECT id FROM users WHERE username = 'sasichai'),
    (SELECT id FROM roles WHERE name = 'user');

    -- 4. Permissions Table
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);

-- 5. Role-Permission Assignment
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_perms_role ON role_permissions(role_id);
CREATE INDEX idx_role_perms_perm ON role_permissions(permission_id);

-- Seed Permissions
INSERT INTO permissions (name, description, resource, action) VALUES
-- Drinks permissions
('drinks:read', 'Can view drinks', 'drinks', 'read'),
('drinks:create', 'Can create drinks', 'drinks', 'create'),
('drinks:update', 'Can update drinks', 'drinks', 'update'),
('drinks:delete', 'Can delete drinks', 'drinks', 'delete'),

-- Foods permissions
('foods:read', 'Can view foods', 'foods', 'read'),
('foods:create', 'Can create foods', 'foods', 'create'),
('foods:update', 'Can update foods', 'foods', 'update'),
('foods:delete', 'Can delete foods', 'foods', 'delete'),

-- Desserts permissions
('desserts:read', 'Can view desserts', 'desserts', 'read'),
('desserts:create', 'Can create desserts', 'desserts', 'create'),
('desserts:update', 'Can update desserts', 'desserts', 'update'),
('desserts:delete', 'Can delete desserts', 'desserts', 'delete'),

-- Users permissions
('users:read', 'Can view users', 'users', 'read'),
('users:create', 'Can create users', 'users', 'create'),
('users:update', 'Can update users', 'users', 'update'),
('users:delete', 'Can delete users', 'users', 'delete'),

-- Roles permissions
('roles:read', 'Can view roles', 'roles', 'read'),
('roles:assign', 'Can assign roles to users', 'roles', 'assign'),
('roles:create', 'Can create new roles', 'roles', 'create'),
('roles:delete', 'Can delete roles', 'roles', 'delete'),

-- Reports permissions
('reports:financial', 'Can view financial reports', 'reports', 'financial'),
('reports:analytics', 'Can view analytics', 'reports', 'analytics');

-- Assign Permissions to Roles

-- Admin: ทุก permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    id
FROM permissions;

INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'editor'),
    id
FROM permissions
WHERE name IN (
    -- Drinks
    'drinks:read', 'drinks:create', 'drinks:update',

    -- Foods
    'foods:read', 'foods:create', 'foods:update',

    -- Desserts
    'desserts:read', 'desserts:create', 'desserts:update',

    -- Allow editor to see users
    'users:read'
);

-- Viewer: read-only
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'viewer'),
    id
FROM permissions
WHERE action = 'read';

-- User books:read
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'user'),
    id
FROM permissions
WHERE name IN ('drinks:read', 'foods:read', 'desserts:read');

-- 6. Refresh Tokens (สำหรับ JWT refresh)
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    replaced_by VARCHAR(500)
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- 7. Audit Logs (สำหรับ tracking)

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,  -- 'login', 'logout', 'create', 'update', 'delete'
    resource VARCHAR(50),           -- 'books', 'users', 'roles'
    resource_id VARCHAR(50),
    details JSONB,
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);