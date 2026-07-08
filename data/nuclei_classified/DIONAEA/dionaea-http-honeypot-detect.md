# Vulnerability: Dionaea HTTP Honeypot - Detect
**Classification:** DIONAEA
**Source:** Nuclei Template (`dionaea-http-honeypot-detect.yaml`)

## Description
Dionaea HTTP honeypot has been identified.
The response to an incorrect HTTP method reveals a possible setup of the Dioanea web application honeypot.

## Vulnerable Code Pattern / Exploit Payload
```http
AAAA / HTTP/1.1
Host: {{Hostname}}
```

