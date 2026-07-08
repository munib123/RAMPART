# Vulnerability: llms.txt - Enumeration
**Classification:** ENUM
**Source:** Nuclei Template (`llms-file-enum.yaml`)

## Description
Detects the presence of a /llms.txt file on the server. This file may be used for internal documentation, configuration, or as a placeholder for third-party integrations. Enumerating such files could reveal sensitive or valuable information if misconfigured or publicly exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/llms.txt
```

