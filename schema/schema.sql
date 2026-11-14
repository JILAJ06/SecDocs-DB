-- SecDocs · Esquema PostgreSQL (idempotente)
-- gen_random_uuid() es nativo desde PostgreSQL 13.

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,          -- bcrypt, costo 12
  role          VARCHAR(20)  NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

-- Un archivo cifrado. La DEK envuelta vive aquí; el binario .enc vive en el storage.
CREATE TABLE IF NOT EXISTS vault_files (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_filename VARCHAR(255) NOT NULL,
  mime_type         VARCHAR(120) NOT NULL,       -- detectado por magic bytes, no el del cliente
  size_bytes        BIGINT NOT NULL CHECK (size_bytes >= 0),
  storage_key       VARCHAR(64) NOT NULL UNIQUE, -- <uuid>.enc, sin extensión real
  wrapped_dek       TEXT,                        -- NULL = purgado (crypto-shredding)
  chunk_size        INT NOT NULL,
  auto_purge        BOOLEAN NOT NULL DEFAULT TRUE, -- destruir al agotarse todos los enlaces
  status            VARCHAR(10) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PURGED')),
  expires_at        TIMESTAMPTZ NOT NULL,
  purged_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status = 'ACTIVE' OR wrapped_dek IS NULL)
);
CREATE INDEX IF NOT EXISTS vault_files_owner_idx ON vault_files (owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS vault_files_expiry_idx ON vault_files (expires_at) WHERE status = 'ACTIVE';

-- Un enlace = un receptor. Contraseña fuera de banda obligatoria.
CREATE TABLE IF NOT EXISTS share_links (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id           UUID NOT NULL REFERENCES vault_files(id) ON DELETE CASCADE,
  recipient_label   VARCHAR(120) NOT NULL,
  token_hash        CHAR(64) NOT NULL UNIQUE,    -- SHA-256 del token; el token nunca se guarda
  password_hash     VARCHAR(255) NOT NULL,       -- bcrypt, costo 12
  max_downloads     INT NOT NULL DEFAULT 1 CHECK (max_downloads BETWEEN 1 AND 3),
  download_count    INT NOT NULL DEFAULT 0 CHECK (download_count >= 0),
  failed_attempts   INT NOT NULL DEFAULT 0,
  locked_until      TIMESTAMPTZ,                 -- retardo progresivo tras fallos
  status            VARCHAR(10) NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE', 'CONSUMED', 'EXPIRED', 'REVOKED', 'LOCKED')),
  ticket_hash       CHAR(64),                    -- ticket de descarga de un solo uso (60 s)
  ticket_expires_at TIMESTAMPTZ,
  expires_at        TIMESTAMPTZ NOT NULL,
  last_access_at    TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (download_count <= max_downloads)
);
CREATE INDEX IF NOT EXISTS share_links_file_idx ON share_links (file_id);
CREATE INDEX IF NOT EXISTS share_links_expiry_idx ON share_links (expires_at) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX IF NOT EXISTS share_links_ticket_idx ON share_links (ticket_hash) WHERE ticket_hash IS NOT NULL;

-- Bitácora de auditoría. Nunca guarda tokens, tickets ni contraseñas.
CREATE TABLE IF NOT EXISTS access_logs (
  id          BIGSERIAL PRIMARY KEY,
  owner_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  file_id     UUID REFERENCES vault_files(id) ON DELETE SET NULL,
  link_id     UUID REFERENCES share_links(id) ON DELETE SET NULL,
  event       VARCHAR(40) NOT NULL,
  ip          VARCHAR(64),
  user_agent  VARCHAR(300),
  detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_logs_owner_idx ON access_logs (owner_id, created_at DESC);
