# Vulnerability: JavaServer Faces Detection
**Classification:** JSF
**Source:** Nuclei Template (`jsf-detect.yaml`)

## Description
Searches for JavaServer Faces content on a URL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

