# Vulnerability: Rustfs - Detect
**Classification:** TECH
**Source:** Nuclei Template (`rustfs-detect.yaml`)

## Description
Detects a Rustfs server, a high-performance, distributed object storage system built in Rust.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/rustfs/console/auth/login
```

