# Vulnerability: NYTimes API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-nytimes.yaml`)

## Description
NYTimes API Test

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.nytimes.com/svc/mostpopular/v2/shared/1.json?api-key={{token}} HTTP/1.1
Host: api.nytimes.com
```

