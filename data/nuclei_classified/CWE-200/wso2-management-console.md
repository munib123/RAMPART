# Vulnerability: WSO2 Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wso2-management-console.yaml`)

## Description
WSO2 Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/carbon/admin/login.jsp
```

