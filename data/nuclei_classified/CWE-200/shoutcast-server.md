# Vulnerability: SHOUTcast Server Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`shoutcast-server.yaml`)

## Description
SHOUTcast Server panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

