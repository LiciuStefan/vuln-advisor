-- Creează bazele de date pentru fiecare serviciu (database-per-service).
-- Rulat automat de PostgreSQL la prima pornire.
CREATE DATABASE advisor_orchestrator;
CREATE DATABASE advisor_ingestion;
CREATE DATABASE advisor_matching;
CREATE DATABASE advisor_reachability;

GRANT ALL PRIVILEGES ON DATABASE advisor_orchestrator  TO advisor;
GRANT ALL PRIVILEGES ON DATABASE advisor_ingestion     TO advisor;
GRANT ALL PRIVILEGES ON DATABASE advisor_matching      TO advisor;
GRANT ALL PRIVILEGES ON DATABASE advisor_reachability  TO advisor;
