# Vulnerability: StackPosts Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`stackposts-installer.yaml`)

## Description
Detects exposed StackPosts installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

