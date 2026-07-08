# Vulnerability: IBM Advanced System Management Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-advanced-system-management.yaml`)

## Description
IBM Advanced System Management panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/cgi?form=1
GET {{BaseURL}}/cgi-bin/cgi
```

