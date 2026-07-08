# Vulnerability: IBM WebSphere Application Server Community Edition Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-websphere-admin-panel.yaml`)

## Description
IBM WebSphere Application Server Community Edition admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console
```

