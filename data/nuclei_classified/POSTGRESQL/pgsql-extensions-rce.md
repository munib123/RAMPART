# Vulnerability: PostgreSQL 8.1  Extensions - Remote Code Execution
**Classification:** POSTGRESQL
**Source:** Nuclei Template (`pgsql-extensions-rce.yaml`)

## Description
PostgreSQL allows for extensions, which are modules providing extra functionality like functions, operators, or types. Starting from version 8.1, these extensions must be compiled with a special header for compatibility with PostgreSQL's extension mechanism.

