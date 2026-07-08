# Vulnerability: Eclipse .project Configuration - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`eclipse-project-exposure.yaml`)

## Description
Detected Eclipse .project configuration file, which may reveal project structure and paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.project
```

