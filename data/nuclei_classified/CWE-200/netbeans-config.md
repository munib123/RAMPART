# Vulnerability: Netbeans Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netbeans-config.yaml`)

## Description
Netbeans configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nbproject/project.properties
```

