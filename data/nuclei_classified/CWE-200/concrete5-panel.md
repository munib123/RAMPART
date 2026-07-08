# Vulnerability: Concrete5 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`concrete5-panel.yaml`)

## Description
Concrete5 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/login
```

