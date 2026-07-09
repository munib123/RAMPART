# Nuclei Template: RoboMongo Credential - Exposure
**Template ID:** robomongo-credential
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`robomongo-credential.yaml`)

## Vulnerability Information & PoC

## Description
A MongoDB credentials file used by RoboMongo was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/db/robomongo.json
GET {{BaseURL}}/robomongo.json
```

## References
- https://robomongo.org/
