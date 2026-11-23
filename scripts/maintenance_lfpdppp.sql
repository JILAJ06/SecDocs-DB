-- SecDocs v2 · Mantenimiento periódico y cumplimiento LFPDPPP
-- Ejecutar de forma programada (p. ej. diario con cron / pg_cron).

-- 1) Purga LFPDPPP: la bitácora auditable (con IP y User-Agent) se conserva 6 meses.
--    daily_stats_rollup NO se purga: es agregada y anónima, se conserva indefinidamente.
DELETE FROM access_logs WHERE created_at < now() - INTERVAL '6 months';

-- 2) Expiración de invitaciones vencidas (invalida también tickets pendientes).
UPDATE workspace_members
   SET status = 'EXPIRED', ticket_hash = NULL, ticket_expires_at = NULL
 WHERE expires_at <= now()
   AND status NOT IN ('REVOKED', 'EXPIRED');

-- 3) Limpieza de la lista negra JWT y de sesiones vencidas.
DELETE FROM revoked_tokens WHERE expires_at <= now();
DELETE FROM user_sessions  WHERE expires_at <= now();
