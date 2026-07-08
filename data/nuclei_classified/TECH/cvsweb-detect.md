# Vulnerability: CVSweb - Detect
**Classification:** TECH
**Source:** Nuclei Template (`cvsweb-detect.yaml`)

## Description
CVSweb is a WWW interface for CVS repositories with which you can browse a file hierarchy on your browser to view each file's revision history in a very handy manner.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

