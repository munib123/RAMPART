# Vulnerability: IBM Maximo Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-maximo-login.yaml`)

## Description
IBM Maximo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/maximo/webclient/login/login.jsp?appservauth=true
```

