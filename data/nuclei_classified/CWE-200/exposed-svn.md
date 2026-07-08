# Vulnerability: SVN Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-svn.yaml`)

## Description
SVN configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.svn/entries
```

