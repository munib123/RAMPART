# Vulnerability: Appwrite Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`appwrite-panel.yaml`)

## Description
Appwrite login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/images/favicon.png
GET {{BaseURL}}/favicon.png
```

