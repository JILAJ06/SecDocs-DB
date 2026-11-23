-- SecDocs v2 · Verificación del esquema (solo lectura)

-- 1) Las 9 tablas esperadas
SELECT table_name
  FROM information_schema.tables
 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
 ORDER BY table_name;

SELECT count(*) AS tablas_encontradas, (count(*) = 9) AS ok
  FROM information_schema.tables
 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
   AND table_name IN ('users','user_sessions','revoked_tokens','vaults','vault_files',
                      'workspace_members','access_logs','user_metrics','daily_stats_rollup');

-- 2) Columnas por tabla
SELECT table_name, ordinal_position, column_name, data_type, character_maximum_length, is_nullable, column_default
  FROM information_schema.columns
 WHERE table_schema = 'public'
 ORDER BY table_name, ordinal_position;

-- 3) Índices únicos y parciales
SELECT tablename, indexname, indexdef
  FROM pg_indexes
 WHERE schemaname = 'public'
   AND (indexdef LIKE 'CREATE UNIQUE%' OR indexdef LIKE '% WHERE %')
 ORDER BY tablename, indexname;

-- 4) Todos los índices
SELECT tablename, indexname, indexdef
  FROM pg_indexes
 WHERE schemaname = 'public'
 ORDER BY tablename, indexname;

-- 5) CHECK constraints de seguridad
SELECT conrelid::regclass AS tabla, conname, pg_get_constraintdef(oid) AS definicion
  FROM pg_constraint
 WHERE contype = 'c' AND connamespace = 'public'::regnamespace
 ORDER BY conrelid::regclass::text, conname;

-- 6) Llaves foráneas y su acción ON DELETE
SELECT conrelid::regclass AS tabla, conname, pg_get_constraintdef(oid) AS definicion
  FROM pg_constraint
 WHERE contype = 'f' AND connamespace = 'public'::regnamespace
 ORDER BY conrelid::regclass::text, conname;
