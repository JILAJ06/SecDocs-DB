# SecDocs · Base de datos

Esquema PostgreSQL de **SecDocs**, una bóveda digital para guardar y compartir documentos confidenciales con cifrado en reposo y acceso por doble canal.

<p align="center">
  <img src="logo.png" alt="Logo de SecDocs" width="160">
</p>

![Captura de la interfaz de SecDocs](preview.png)

![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-postgres:16--alpine-2496ED?logo=docker&logoColor=white)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-green)

## Qué es SecDocs

SecDocs permite que una persona cree **bóvedas** con fecha de expiración, suba documentos a ellas e invite a otras personas a descargarlos de forma controlada. Este repositorio contiene el esquema relacional, los scripts de verificación y mantenimiento y un `docker-compose.yml` para levantar PostgreSQL en local.

- [SecDocs-Backend](https://github.com/JILAJ06/SecDocs-Backend) es el único que se conecta a la base (`DATABASE_URL`).
- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend) solo habla con la API del backend; nunca accede a la base.
- Los archivos de la versión 1 están en [`legacy/`](legacy/).

Lo que garantiza el esquema:

- **Ningún secreto en texto plano.**
  - Las contraseñas se guardan con bcrypt.
  - De los tokens de invitación y los tickets solo se guarda su hash SHA-256.
  - Las llaves de bóveda (`KEK`) y de archivo (`DEK`) se guardan envueltas con AES-256-GCM.
- **Crypto-shredding garantizado por el motor.** Restricciones `CHECK` impiden marcar una bóveda o un archivo como destruido sin borrar antes su llave envuelta.
- **Tickets de un solo uso sin condiciones de carrera.** Un índice único parcial y un `UPDATE ... RETURNING` atómico hacen que, ante peticiones simultáneas, solo una consuma el ticket.
- **Límite de descargas en la base.** `CHECK (download_count <= max_downloads)` impide superar el límite aunque falle la aplicación.
- **Retención de la bitácora (LFPDPPP).** `access_logs` guarda IP y *User-Agent* y se purga a los 6 meses. `daily_stats_rollup` solo guarda agregados anónimos y se conserva.

## Diagrama entidad-relación

```mermaid
erDiagram
  users ||--o{ user_sessions : "tiene"
  users ||--o{ vaults : "posee"
  users ||--o{ vault_files : "posee"
  users ||--o{ access_logs : "genera"
  users ||--|| user_metrics : "métricas"
  users ||--o{ daily_stats_rollup : "agregados"
  vaults ||--o{ vault_files : "contiene"
  vaults ||--o{ workspace_members : "invita"
  vaults |o--o{ access_logs : "registra"
  vault_files |o--o{ access_logs : "registra"
  workspace_members |o--o{ access_logs : "registra"

  users {
    UUID id PK
    VARCHAR email
    VARCHAR password_hash
    VARCHAR role
    TIMESTAMPTZ created_at
  }
  user_sessions {
    VARCHAR jti PK
    UUID user_id FK
    TIMESTAMPTZ expires_at
  }
  revoked_tokens {
    VARCHAR jti PK
    TIMESTAMPTZ revoked_at
    TIMESTAMPTZ expires_at
  }
  vaults {
    UUID id PK
    UUID owner_id FK
    TEXT wrapped_kek
    VARCHAR status
    TIMESTAMPTZ expires_at
  }
  vault_files {
    UUID id PK
    UUID vault_id FK
    UUID owner_id FK
    VARCHAR storage_key
    TEXT wrapped_dek
    VARCHAR status
  }
  workspace_members {
    UUID id PK
    UUID vault_id FK
    CHAR token_hash
    CHAR ticket_hash
    INT max_downloads
    INT download_count
    VARCHAR status
  }
  access_logs {
    BIGSERIAL id PK
    UUID owner_id FK
    UUID vault_id FK
    UUID file_id FK
    UUID member_id FK
    VARCHAR event
    JSONB detail
  }
  user_metrics {
    UUID owner_id PK
    BIGINT total_storage_bytes
  }
  daily_stats_rollup {
    BIGSERIAL id PK
    UUID owner_id FK
    DATE stat_date
  }
```

`revoked_tokens` no tiene llaves foráneas: es una lista negra de `jti` que se consulta en cada petición.

## Seguridad en el esquema

### Llaves y secretos

La jerarquía de cifrado es `MASTER_ENCRYPTION_KEY (MEK)` → `KEK` por bóveda → `DEK` por archivo, con AES-256-GCM. La MEK vive solo en el entorno del backend, nunca en la base.

| Dato | Cómo se guarda |
|---|---|
| `users.password_hash`, `workspace_members.password_hash` | bcrypt, costo 12 |
| `workspace_members.token_hash`, `ticket_hash` | SHA-256 (`CHAR(64)`) |
| `vaults.wrapped_kek` | KEK cifrada con la MEK, formato `iv:authTag:ciphertext` en base64 |
| `vault_files.wrapped_dek` | DEK cifrada con la KEK de su bóveda, mismo formato |
| `vault_files.iv`, `auth_tag` | Base64, del cifrado AES-256-GCM del archivo |

### Crypto-shredding

- `vaults`: `CHECK (status <> 'PURGED' OR wrapped_kek IS NULL)`
- `vault_files`: `CHECK (status = 'ACTIVE' OR wrapped_dek IS NULL)`

PostgreSQL rechaza que una bóveda pase a `PURGED`, o que un archivo deje de estar `ACTIVE`, sin haber puesto antes su llave envuelta en `NULL`. Sin esa llave, el binario `.enc` guardado en Cloudflare R2 es irrecuperable. `scripts/demo_crypto_shredding.sql` lo demuestra.

### Tickets y descargas

- `wm_ticket_idx` es un índice único parcial (`WHERE ticket_hash IS NOT NULL`): dos miembros no pueden tener el mismo ticket vigente.
- El backend consume el ticket con un solo `UPDATE ... SET ticket_hash = NULL, download_count = download_count + 1 ... RETURNING`. Si llegan peticiones simultáneas, solo una obtiene la fila.
- `CHECK (download_count <= max_downloads)` y `CHECK (max_downloads BETWEEN 1 AND 10)` protegen el límite de descargas.

### Retención (LFPDPPP)

- `access_logs` es la bitácora auditable, con IP y *User-Agent*. Se purga a los 6 meses, con `scripts/maintenance_lfpdppp.sql` o con la tarea programada del backend.
- `daily_stats_rollup` solo guarda agregados anónimos por día y no se purga. El backend lo actualiza con un *upsert* atómico (`INSERT ... ON CONFLICT (owner_id, stat_date) DO UPDATE`).

## Diccionario de datos

### users
| Columna | Tipo | Notas |
|---|---|---|
| id | UUID PK | `gen_random_uuid()` |
| email | VARCHAR(255) | Único sin distinguir mayúsculas (`users_email_lower_idx`) |
| password_hash | VARCHAR(255) | bcrypt, costo 12 |
| role | VARCHAR(20) | `user` \| `admin` |
| created_at | TIMESTAMPTZ | |

### user_sessions
| Columna | Tipo | Notas |
|---|---|---|
| jti | VARCHAR(128) PK | ID del JWT |
| user_id | UUID FK → users | `ON DELETE CASCADE` |
| ip, user_agent | VARCHAR(64), VARCHAR(300) | Opcionales |
| created_at, expires_at | TIMESTAMPTZ | |

### revoked_tokens
| Columna | Tipo | Notas |
|---|---|---|
| jti | VARCHAR(128) PK | |
| revoked_at, expires_at | TIMESTAMPTZ | Índice por expiración para la limpieza |

### vaults
| Columna | Tipo | Notas |
|---|---|---|
| id | UUID PK | |
| owner_id | UUID FK → users | `ON DELETE CASCADE` |
| name | VARCHAR(150) | |
| wrapped_kek | TEXT | `NULL` si la bóveda fue destruida |
| status | VARCHAR(15) | `ACTIVE`, `LOCKED`, `EXPIRED`, `PURGED` |
| expires_at, purged_at, created_at | TIMESTAMPTZ | |

### vault_files
| Columna | Tipo | Notas |
|---|---|---|
| id | UUID PK | |
| vault_id | UUID FK → vaults | `ON DELETE CASCADE` |
| owner_id | UUID FK → users | `ON DELETE CASCADE` |
| original_filename | VARCHAR(255) | |
| mime_type | VARCHAR(120) | Detectado por *magic bytes* |
| size_bytes | BIGINT | `>= 0` |
| storage_key | VARCHAR(80) UNIQUE | `<uuid>.enc` en Cloudflare R2 |
| wrapped_dek | TEXT | `NULL` = crypto-shredding |
| iv, auth_tag | VARCHAR(64) | Base64 (12 y 16 bytes) |
| status | VARCHAR(10) | `ACTIVE` \| `PURGED` |
| purged_at, created_at | TIMESTAMPTZ | |

### workspace_members
| Columna | Tipo | Notas |
|---|---|---|
| id | UUID PK | |
| vault_id | UUID FK → vaults | `ON DELETE CASCADE` |
| recipient_email, recipient_label | VARCHAR(255), VARCHAR(120) | |
| token_hash | CHAR(64) UNIQUE | SHA-256 del token de invitación |
| password_hash | VARCHAR(255) | bcrypt, costo 12 (clave del Canal 2) |
| max_downloads | INT | De 1 a 10, por defecto 3 |
| download_count | INT | `>= 0` y `<= max_downloads` |
| failed_attempts, locked_until | INT, TIMESTAMPTZ | Bloqueo temporal |
| status | VARCHAR(20) | `PENDING`, `ACCEPTED`, `TEMP_LOCKED`, `REVOKED`, `EXPIRED` |
| ticket_hash, ticket_expires_at | CHAR(64), TIMESTAMPTZ | Ticket de un solo uso (60 s) |
| expires_at, last_access_at, created_at | TIMESTAMPTZ | |

### access_logs
| Columna | Tipo | Notas |
|---|---|---|
| id | BIGSERIAL PK | |
| owner_id | UUID FK → users | `ON DELETE CASCADE` |
| vault_id, file_id, member_id | UUID FK | `ON DELETE SET NULL` |
| event | VARCHAR(50) | |
| ip, user_agent | VARCHAR(64), VARCHAR(300) | |
| detail | JSONB | Por defecto `{}` |
| created_at | TIMESTAMPTZ | Retención de 6 meses |

### user_metrics
| Columna | Tipo | Notas |
|---|---|---|
| owner_id | UUID PK, FK → users | `ON DELETE CASCADE` |
| total_storage_bytes | BIGINT | |
| total_files_active, total_vaults_active | INT | |
| updated_at | TIMESTAMPTZ | |

### daily_stats_rollup
| Columna | Tipo | Notas |
|---|---|---|
| id | BIGSERIAL PK | |
| owner_id | UUID FK → users | `ON DELETE CASCADE` |
| stat_date | DATE | `UNIQUE (owner_id, stat_date)` |
| total_downloads, total_failed_attempts, unique_visitors | INT | Agregados anónimos |

## Stack tecnológico

| Herramienta | Versión | Uso |
|---|---|---|
| PostgreSQL | 16 (imagen `postgres:16-alpine`) | Motor de base de datos |
| `gen_random_uuid()` | incluida en PostgreSQL 13+ | Llaves primarias UUID |
| Docker Compose | — | Base local con volumen persistente |

## Requisitos previos

- Docker con Docker Compose, para la base local.
- O una instancia de PostgreSQL 16 propia o en Supabase, donde se aplica `migrations/001_init.sql`.
- `psql`, si vas a ejecutar los scripts fuera del contenedor.

## Ejecución en local

```bash
# 1. Variables de entorno
cp .env.example .env            # en PowerShell: Copy-Item .env.example .env

# 2. Levantar PostgreSQL. La primera vez, al crear el volumen,
#    aplica migrations/001_init.sql automáticamente
docker compose up -d
```

La base queda publicada solo en `127.0.0.1`, en el puerto `POSTGRES_PORT` (por defecto `5432`).

Scripts disponibles:

```bash
# Aplicar el esquema a mano (es idempotente: CREATE ... IF NOT EXISTS)
docker compose exec -T db psql -U secdocs -d secdocs < migrations/001_init.sql

# Verificar que existan las 9 tablas, sus columnas y restricciones (solo lectura)
docker compose exec -T db psql -U secdocs -d secdocs < scripts/verify_schema.sql

# Demostración de crypto-shredding (termina en ROLLBACK, no deja datos)
docker compose exec -T db psql -U secdocs -d secdocs < scripts/demo_crypto_shredding.sql

# Mantenimiento: purga de bitácora, invitaciones vencidas y tokens expirados
docker compose exec -T db psql -U secdocs -d secdocs < scripts/maintenance_lfpdppp.sql
```

Para empezar desde cero (borra el volumen y todos los datos):

```bash
docker compose down -v
```

## Variables de entorno

Se definen en `.env` (a partir de `.env.example`) y nunca se suben al repositorio. Los ejemplos son ficticios.

| Variable | Descripción | Ejemplo |
|---|---|---|
| `POSTGRES_USER` | Usuario de PostgreSQL (por defecto `secdocs`) | `secdocs` |
| `POSTGRES_PASSWORD` | Contraseña de ese usuario | *(una contraseña propia)* |
| `POSTGRES_DB` | Nombre de la base (por defecto `secdocs`) | `secdocs` |
| `POSTGRES_PORT` | Puerto publicado en `127.0.0.1` (por defecto `5432`) | `5432` |
| `DATABASE_URL` | Cadena que debe usar SecDocs-Backend para esta base | `postgresql://usuario:contraseña@127.0.0.1:5432/secdocs` |

## Conexión con el backend

- Copia la `DATABASE_URL` en el `.env` de [SecDocs-Backend](https://github.com/JILAJ06/SecDocs-Backend).
- **Migraciones:** el backend trae su propia copia de `001_init.sql` (`src/db/migrations/`) y la aplica al arrancar. Es el mismo esquema, solo cambian los comentarios.
- **Supabase:** usa el *Session Pooler* (puerto `5432`) y `DATABASE_SSL=true` en el backend.
- **Puerto 5432:** el `docker-compose.yml` del backend levanta su propio PostgreSQL en ese mismo puerto. Usa uno de los dos, o cambia `POSTGRES_PORT` en este repositorio.

Repositorios del proyecto:

- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend): interfaz web en Next.js.
- [SecDocs-Backend](https://github.com/JILAJ06/SecDocs-Backend): API REST en Node.js y Express.
- **SecDocs-DB**: este repositorio.

## Estructura de carpetas

```text
migrations/
  001_init.sql                 esquema v2 completo (9 tablas, índices y restricciones)
scripts/
  verify_schema.sql            verificación de tablas, columnas y restricciones
  demo_crypto_shredding.sql    demostración de las invariantes de crypto-shredding
  maintenance_lfpdppp.sql      purga de bitácora y limpieza periódica
legacy/
  README_v1.md                 documentación de la versión 1
  schema_v1/schema.sql         esquema de la versión 1
docker-compose.yml             PostgreSQL 16 local con volumen persistente
.env.example                   variables de ejemplo
```

## Seguridad

Buenas prácticas del repositorio:

- La base solo se publica en `127.0.0.1`: no queda expuesta a la red.
- Los datos de prueba de los scripts son ficticios (`demo@secdocs.test`) y la demostración termina en `ROLLBACK`.
- Ningún script ni migración contiene llaves, contraseñas reales ni la MEK.

Qué **no** subir al repositorio:

- `.env` ni ninguna copia con valores reales. El `.gitignore` ya excluye `.env` y `.env.*`, salvo `.env.example`.
- Contraseñas o cadenas de conexión de Supabase o de producción.
- Volcados y respaldos (`*.dump`, `*.sql.gz`, `*.bak`) ni la carpeta `pgdata/`; el `.gitignore` ya los excluye.
- Datos reales de usuarios, correos, IP o registros de `access_logs`.

## Autores

- Alexander Jiménez
- Sayd Quevedo

Proyecto de la materia **Seguridad Informática**, Universidad Politécnica de Chiapas.

## Licencia

Distribuido bajo la licencia MIT. Consulta [LICENSE.txt](LICENSE.txt).
