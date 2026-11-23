-- SecDocs v2 · Demo de Crypto-Shredding e invariantes SQL
-- Todo corre dentro de una transacción que termina en ROLLBACK (no deja datos).
-- Cada prueba negativa usa un bloque DO que captura check_violation y lo reporta.

BEGIN;

-- Datos de prueba
INSERT INTO users (id, email, password_hash)
VALUES ('00000000-0000-0000-0000-000000000001', 'demo@secdocs.test', 'bcrypt-demo');

INSERT INTO vaults (id, owner_id, name, wrapped_kek, expires_at)
VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-000000000001',
        'Bóveda demo', 'iv:tag:kek-cifrada', now() + INTERVAL '7 days');

INSERT INTO vault_files (id, vault_id, owner_id, original_filename, mime_type, size_bytes,
                         storage_key, wrapped_dek, iv, auth_tag)
VALUES ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-0000000000a1',
        '00000000-0000-0000-0000-000000000001', 'contrato.pdf', 'application/pdf', 1024,
        '00000000-0000-0000-0000-0000000000f1.enc', 'iv:tag:dek-cifrada', 'aXY=', 'dGFn');

INSERT INTO workspace_members (id, vault_id, recipient_email, token_hash, password_hash,
                               max_downloads, ticket_hash, ticket_expires_at, expires_at)
VALUES ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1',
        'dest@secdocs.test', repeat('a', 64), 'bcrypt-demo', 1,
        repeat('b', 64), now() + INTERVAL '60 seconds', now() + INTERVAL '7 days');

-- Prueba 1: archivo PURGED sin destruir wrapped_dek -> debe FALLAR
DO $$
BEGIN
  UPDATE vault_files SET status = 'PURGED', purged_at = now()
   WHERE id = '00000000-0000-0000-0000-0000000000f1';
  RAISE EXCEPTION 'FALLO DE LA DEMO: se permitió PURGED con wrapped_dek';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'OK 1: bloqueado por CHECK -> %', SQLERRM;
END $$;

-- Prueba 2: bóveda PURGED sin destruir wrapped_kek -> debe FALLAR
DO $$
BEGIN
  UPDATE vaults SET status = 'PURGED', purged_at = now()
   WHERE id = '00000000-0000-0000-0000-0000000000a1';
  RAISE EXCEPTION 'FALLO DE LA DEMO: se permitió PURGED con wrapped_kek';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'OK 2: bloqueado por CHECK -> %', SQLERRM;
END $$;

-- Prueba 3: consumo atómico del ticket (una sola sentencia)
UPDATE workspace_members
   SET ticket_hash = NULL,
       ticket_expires_at = NULL,
       download_count = download_count + 1,
       last_access_at = now()
 WHERE ticket_hash = repeat('b', 64)
   AND ticket_expires_at > now()
   AND download_count < max_downloads
RETURNING id, download_count, max_downloads, ticket_hash;

-- Reintento con el mismo ticket: 0 filas (ticket de un solo uso)
UPDATE workspace_members
   SET ticket_hash = NULL, download_count = download_count + 1
 WHERE ticket_hash = repeat('b', 64)
RETURNING id;

-- Prueba 4: superar max_downloads (1) -> debe FALLAR
DO $$
BEGIN
  UPDATE workspace_members SET download_count = download_count + 1
   WHERE id = '00000000-0000-0000-0000-0000000000b1';
  RAISE EXCEPTION 'FALLO DE LA DEMO: se superó max_downloads';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'OK 4: bloqueado por CHECK -> %', SQLERRM;
END $$;

-- Crypto-shredding correcto: destruir la llave y marcar PURGED en la misma sentencia
UPDATE vault_files SET wrapped_dek = NULL, status = 'PURGED', purged_at = now()
 WHERE id = '00000000-0000-0000-0000-0000000000f1'
RETURNING id, status, wrapped_dek;

UPDATE vaults SET wrapped_kek = NULL, status = 'PURGED', purged_at = now()
 WHERE id = '00000000-0000-0000-0000-0000000000a1'
RETURNING id, status, wrapped_kek;

ROLLBACK;
