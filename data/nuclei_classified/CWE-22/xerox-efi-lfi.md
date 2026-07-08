# Vulnerability: Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`xerox-efi-lfi.yaml`)

## Description
Xerox DC260 EFI Fiery Controller Webtools 2.0 is vulnerable to local file inclusion because input passed thru the 'file' GET parameter in 'forceSave.php' script is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wt3/forceSave.php?file=/etc/passwd
```

