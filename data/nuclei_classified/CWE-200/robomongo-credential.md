# Vulnerability: RoboMongo Credential - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`robomongo-credential.yaml`)

## Description
A MongoDB credentials file used by RoboMongo was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/db/robomongo.json
GET {{BaseURL}}/robomongo.json
```

