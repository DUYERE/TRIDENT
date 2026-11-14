-- TRIDENT least-privilege role template (example only).
-- Run as a PostgreSQL superuser after selecting the target database.
-- Replace the database name and set passwords via a secret manager; never commit real secrets.
--
-- Roles:
--   trident_migrator  - DDL/migrations only
--   trident_runtime   - application DML, no DDL
--   trident_readonly  - read-only reporting/console queries
--
-- If tables were created by a different role, change FOR ROLE below to the
-- actual table owner before running the ALTER DEFAULT PRIVILEGES statements.

CREATE ROLE trident_migrator LOGIN PASSWORD '<set-in-secret-manager>';
CREATE ROLE trident_runtime LOGIN PASSWORD '<set-in-secret-manager>';
CREATE ROLE trident_readonly LOGIN PASSWORD '<set-in-secret-manager>';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT CONNECT ON DATABASE trident TO trident_migrator, trident_runtime, trident_readonly;
GRANT USAGE, CREATE ON SCHEMA public TO trident_migrator;
GRANT USAGE ON SCHEMA public TO trident_runtime, trident_readonly;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trident_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trident_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO trident_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO trident_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE trident_migrator IN SCHEMA public
    GRANT SELECT ON TABLES TO trident_readonly;
