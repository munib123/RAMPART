# Vulnerability: Wing FTP Service - Detect
**Classification:** TECH
**Source:** Nuclei Template (`wing-ftp-service-detect.yaml`)

## Description
The File Transfer Protocol (FTP) is a standard network protocol used to transfer computer files between a client and server on a computer network.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

