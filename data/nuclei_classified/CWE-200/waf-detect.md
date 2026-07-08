# Vulnerability: WAF Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`waf-detect.yaml`)

## Description
A web application firewall was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_=<script>alert(1)</script>
```

