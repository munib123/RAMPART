# Vulnerability: IBM MQ Web Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-mqseries-web-console.yaml`)

## Description
IBM MQ Web Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ibmmq/console/login.html
```

