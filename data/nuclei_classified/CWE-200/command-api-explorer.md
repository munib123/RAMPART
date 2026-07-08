# Vulnerability: Command API Explorer Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`command-api-explorer.yaml`)

## Description
Command API Explorer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/explorer.html
```

