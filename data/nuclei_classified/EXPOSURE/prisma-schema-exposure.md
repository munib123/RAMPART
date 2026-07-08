# Vulnerability: Exposed Prisma Database Schema - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`prisma-schema-exposure.yaml`)

## Description
Prisma is a modern ORM extremely popular in the Node.js and TypeScript (Next.js/Express) ecosystems. Developers often accidentally expose the `prisma/` folder in web directories during deployments or Docker builds. This template checks for the exposure of the `schema.prisma` file, which typically contains the complete internal database table definitions, architectures, and the database connection strings (URLs) pointing to AWS RDS, PostgreSQL, or SQLite databases.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/schema.prisma
GET {{BaseURL}}/prisma/schema.prisma
GET {{BaseURL}}/src/prisma/schema.prisma
GET {{BaseURL}}/db/schema.prisma
GET {{BaseURL}}/.prisma/schema.prisma
```

