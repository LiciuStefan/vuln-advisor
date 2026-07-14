# Container-job minimal: rulează Flyway pe fiecare bază și iese.
# NU e o aplicație Spring — doar migrează schema, apoi se oprește.
FROM flyway/flyway:11-alpine

# Copiază migrările (organizate per bază) și scriptul de rulare
COPY sql /flyway/sql
COPY migrate.sh /flyway/migrate.sh

# Suprascrie entrypoint-ul implicit (care e comanda flyway) cu scriptul nostru,
# care rulează flyway o dată per bază.
ENTRYPOINT ["/bin/sh", "/flyway/migrate.sh"]
