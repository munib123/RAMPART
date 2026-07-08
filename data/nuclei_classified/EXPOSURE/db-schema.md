# Vulnerability: Discover db schema files
**Classification:** EXPOSURE
**Source:** Nuclei Template (`db-schema.yaml`)

## Description
This file is auto-generated from the current state of the database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/db/schema.rb
GET {{BaseURL}}/database/schema.rb
GET {{BaseURL}}/schema.rb
```

