# Nuclei Template: db.xml File - Detect
**Template ID:** db-xml-file
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`db-xml-file.yaml`)

## Vulnerability Information & PoC

## Description
db.xml file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/db.xml
```

