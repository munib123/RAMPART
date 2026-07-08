# Vulnerability: db.xml File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`db-xml-file.yaml`)

## Description
db.xml file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/db.xml
```

