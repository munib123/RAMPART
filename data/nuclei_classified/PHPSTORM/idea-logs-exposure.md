# Vulnerability: Public .idea Folder containing http logs
**Classification:** PHPSTORM
**Source:** Nuclei Template (`idea-logs-exposure.yaml`)

## Description
Searches for .idea Folder for http-requests-log.http and http-client.cookies file

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.idea/httpRequests/http-requests-log.http
GET {{BaseURL}}/.idea/httpRequests/http-client.cookies
```

