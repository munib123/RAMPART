# Vulnerability: PostgreSQL List Database
**Classification:** JS
**Source:** Nuclei Template (`pgsql-list-database.yaml`)

## Description
A single Postgres server process can manage multiple databases at the same time. Each database is stored as a separate set of files in its own directory within the server’s data directory.

