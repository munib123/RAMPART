# Vulnerability: Amazon S3 Torrent Download - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`s3-torrent.yaml`)

## Description
Amazon S3 Torrent download was detected, which can allow a malicious user to download files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?torrent
```

