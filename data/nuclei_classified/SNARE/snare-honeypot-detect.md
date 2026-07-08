# Vulnerability: Snare Honeypot - Detect
**Classification:** SNARE
**Source:** Nuclei Template (`snare-honeypot-detect.yaml`)

## Description
Snare honeypot has been identified.
The response to an incorrect HTTP version reveals a possible setup of the Snare web application honeypot.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1337
Host: {{Hostname}}
```

