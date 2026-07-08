# Vulnerability: Icecast Streaming Media Server Information Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`icecast-mediaserver-detect.yaml`)

## Description
Icecast Streaming Media Server information panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/server_version.xsl
```

