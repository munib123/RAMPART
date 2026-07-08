# Vulnerability: Google Books API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`google-books.yaml`)

## Description
Google Books

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.googleapis.com/books/v1/volumes/zyTCAlFPjgYC?key={{token}}
```

