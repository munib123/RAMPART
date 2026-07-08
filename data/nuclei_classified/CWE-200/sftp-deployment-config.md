# Vulnerability: Atom SFTP Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sftp-deployment-config.yaml`)

## Description
Atom SFTP deployment configuration file was detected. File contains server details and credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/deployment-config.json
```

