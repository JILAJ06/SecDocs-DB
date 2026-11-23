-- SecDocs v2 · Esquema PostgreSQL 16+ (idempotente)

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL, -- bcrypt costo 12
  role          VARCHAR(20)  NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

-- Sesiones activas para la pantalla de Seguridad
CREATE TABLE IF NOT EXISTS user_sessions (
  jti         VARCHAR(128) PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip          VARCHAR(64),
  user_agent  VARCHAR(300),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id);

-- Lista negra de alta velocidad (Kill-switch)
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti         VARCHAR(128) PRIMARY KEY,
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expiry_idx ON revoked_tokens (expires_at);

-- Bóvedas (Workspaces) con KEK propia
CREATE TABLE IF NOT EXISTS vaults (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        VARCHAR(150) NOT NULL,
  wrapped_kek TEXT, -- NULL si la bóveda fue purgada
  status      VARCHAR(15) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'LOCKED', 'EXPIRED', 'PURGED')),
  expires_at  TIMESTAMPTZ NOT NULL,
  purged_at   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status <> 'PURGED' OR wrapped_kek IS NULL)
);
CREATE INDEX IF NOT EXISTS vaults_owner_idx ON vaults (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS vaults_expiry_idx ON vaults (expires_at) WHERE status = 'ACTIVE';

-- Archivos cifrados dentro de una bóveda (binario .enc en Cloudflare R2)
CREATE TABLE IF NOT EXISTS vault_files (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id          UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  owner_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_filename VARCHAR(255) NOT NULL,
  mime_type         VARCHAR(120) NOT NULL, -- detectado por magic bytes
  size_bytes        BIGINT NOT NULL CHECK (size_bytes >= 0),
  storage_key       VARCHAR(80) NOT NULL UNIQUE, -- <uuid>.enc
  wrapped_dek       TEXT, -- DEK cifrada con la KEK de la bóveda; NULL = crypto-shredding
  iv                VARCHAR(64), -- IV en base64 para AES-256-GCM (12 bytes)
  auth_tag          VARCHAR(64), -- AuthTag en base64 para AES-256-GCM (16 bytes)
  status            VARCHAR(10) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PURGED')),
  purged_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status = 'ACTIVE' OR wrapped_dek IS NULL)
);
CREATE INDEX IF NOT EXISTS vault_files_vault_idx ON vault_files (vault_id, created_at DESC);

-- Invitaciones y miembros por bóveda (Correo vinculado + Canal 2)
CREATE TABLE IF NOT EXISTS workspace_members (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id          UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  recipient_email   VARCHAR(255) NOT NULL,
  recipient_label   VARCHAR(120),
  token_hash        CHAR(64) NOT NULL UNIQUE, -- SHA-256 del token de invitación
  password_hash     VARCHAR(255) NOT NULL,    -- bcrypt costo 12 (clave enviada por correo Canal 2)
  max_downloads     INT NOT NULL DEFAULT 3 CHECK (max_downloads BETWEEN 1 AND 10),
  download_count    INT NOT NULL DEFAULT 0 CHECK (download_count >= 0),
  failed_attempts   INT NOT NULL DEFAULT 0,
  locked_until      TIMESTAMPTZ,
  status            VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'ACCEPTED', 'TEMP_LOCKED', 'REVOKED', 'EXPIRED')),
  ticket_hash       CHAR(64), -- SHA-256 del ticket de descarga de un solo uso (TTL 60s)
  ticket_expires_at TIMESTAMPTZ,
  expires_at        TIMESTAMPTZ NOT NULL,
  last_access_at    TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (download_count <= max_downloads)
);
CREATE INDEX IF NOT EXISTS wm_vault_idx ON workspace_members (vault_id);
CREATE INDEX IF NOT EXISTS wm_email_idx ON workspace_members (lower(recipient_email));
CREATE UNIQUE INDEX IF NOT EXISTS wm_ticket_idx ON workspace_members (ticket_hash) WHERE ticket_hash IS NOT NULL;

-- Bitácora de auditoría (Retención 6 meses por LFPDPPP)
CREATE TABLE IF NOT EXISTS access_logs (
  id          BIGSERIAL PRIMARY KEY,
  owner_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  vault_id    UUID REFERENCES vaults(id) ON DELETE SET NULL,
  file_id     UUID REFERENCES vault_files(id) ON DELETE SET NULL,
  member_id   UUID REFERENCES workspace_members(id) ON DELETE SET NULL,
  event       VARCHAR(50) NOT NULL,
  ip          VARCHAR(64),
  user_agent  VARCHAR(300),
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_logs_owner_idx ON access_logs (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_created_idx ON access_logs (created_at);

-- Métricas de usuario en tiempo real
CREATE TABLE IF NOT EXISTS user_metrics (
  owner_id            UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  total_storage_bytes BIGINT NOT NULL DEFAULT 0,
  total_files_active  INT NOT NULL DEFAULT 0,
  total_vaults_active INT NOT NULL DEFAULT 0,
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Estadísticas agregadas anónimas (Conservación indefinida)
CREATE TABLE IF NOT EXISTS daily_stats_rollup (
  id                    BIGSERIAL PRIMARY KEY,
  owner_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stat_date             DATE NOT NULL,
  total_downloads       INT NOT NULL DEFAULT 0,
  total_failed_attempts INT NOT NULL DEFAULT 0,
  unique_visitors       INT NOT NULL DEFAULT 0,
  UNIQUE (owner_id, stat_date)
);
