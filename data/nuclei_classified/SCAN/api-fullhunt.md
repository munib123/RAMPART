# Vulnerability: FullHunt API Test
**Classification:** SCAN
**Source:** Nuclei Template (`api-fullhunt.yaml`)

## Description
FullHunt holds one of the largest Databases for external attack surfaces of the entire Internet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fullhunt.io/api/v1/domain/interact.sh/details
```

