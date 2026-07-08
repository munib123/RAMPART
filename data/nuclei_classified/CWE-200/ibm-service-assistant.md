# Vulnerability: IBM Service Assistant Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ibm-service-assistant.yaml`)

## Description
IBM Service Assistant login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/service/
```

