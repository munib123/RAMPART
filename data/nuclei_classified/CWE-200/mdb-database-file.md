# Vulnerability: Microsoft Access Database File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mdb-database-file.yaml`)

## Description
Microsoft Access database file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{mdbPaths}} HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Accept-Language: en-US,en;q=0.9
```

