# Vulnerability: MyBB Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mybb-forum-detect.yaml`)

## Description
MyBB login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/portal.php
```

