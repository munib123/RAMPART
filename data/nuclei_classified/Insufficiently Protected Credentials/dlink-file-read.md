# Nuclei Template: D-Link - Local File Inclusion
**Template ID:** dlink-file-read
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`d-link-arbitary-fileread.yaml`)

## Vulnerability Information & PoC

## Description
D-Link is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/cgi-bin/webproc
```

## References
- https://suid.ch/research/DAP-2020_Preauth_RCE_Chain.html
