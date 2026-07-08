# Vulnerability: Mongo Express - Unauthenticated Access
**Classification:** MONGO
**Source:** Nuclei Template (`unauthenticated-mongo-express.yaml`)

## Description
Mongo Express was able to be access with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/mongo-express/
GET {{BaseURL}}/db/admin/system.users
```

