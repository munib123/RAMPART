# Vulnerability: Open Page Rank API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-open-page-rank.yaml`)

## Description
API for calculating and comparing metrics of different websites using Page Rank algorithm

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://openpagerank.com/api/v1.0/getPageRank?domains[]=google.com HTTP/1.1
Host: openpagerank.com
API-OPR: {{token}}
```

