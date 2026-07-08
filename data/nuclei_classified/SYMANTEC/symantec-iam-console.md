# Vulnerability: Symantec Identity Manager Management Console
**Classification:** SYMANTEC
**Source:** Nuclei Template (`symantec-iam-console.yaml`)

## Description
Management Console to administrate Symantec Identity Manager environment, authentication is sometimes disabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iam/immanage/login.jsp
```

