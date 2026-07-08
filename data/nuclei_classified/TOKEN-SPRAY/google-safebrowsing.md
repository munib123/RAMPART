# Vulnerability: Google Safe Browsing API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`google-safebrowsing.yaml`)

## Description
Google Link/Domain Flagging

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key={{token}} HTTP/1.1
Host: safebrowsing.googleapis.com
Content-Type: application/json
```

