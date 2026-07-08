# Vulnerability: WAF Fuzzing
**Classification:** CWE-200
**Source:** Nuclei Template (`waf-fuzz.yaml`)

## Description
A web application firewall was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_={{whatwaf-payloads}}

GET /?_={{whatwaf-payloads}} HTTP/1.1
Host: {{Hostname}}
```

