# Vulnerability: Jenkins Users - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`jenkins-users-exposure.yaml`)

## Description
Detected an exposed Jenkins asynchPeople endpoint that discloses user information (e.g., users, full names, and profile URLs) allowing user enumeration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/asynchPeople/api/json
```

