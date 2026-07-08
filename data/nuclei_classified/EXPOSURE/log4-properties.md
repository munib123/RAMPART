# Vulnerability: Log4j Properties - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`log4-properties.yaml`)

## Description
Log4j Properties file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/log4j.properties
```

