# Nuclei Template: Atom SFTP Configuration File - Detect
**Template ID:** sftp-deployment-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`sftp-deployment-config.yaml`)

## Vulnerability Information & PoC

## Description
Atom SFTP deployment configuration file was detected. File contains server details and credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/deployment-config.json
```

## References
- https://atom.io/packages/sftp-deployment
