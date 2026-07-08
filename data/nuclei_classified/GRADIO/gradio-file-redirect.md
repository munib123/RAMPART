# Vulnerability: Gradio - Open Redirect
**Classification:** GRADIO
**Source:** Nuclei Template (`gradio-file-redirect.yaml`)

## Description
An open redirect vulnerability in Gradio allows attackers to craft malicious URLs that redirect users to external, potentially harmful sites without proper validation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gradio_api/file=http://example.com
GET {{BaseURL}}/file=http://example.com
```

