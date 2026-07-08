# Vulnerability: Marimo > 0.9.20 - Proxy Abuse
**Classification:** CWE-400
**Source:** Nuclei Template (`marimo-proxy-abuse.yaml`)

## Description
The /mpl/<port>/<route> endpoint, which is accessible without authentication on default Marimo installations allows for external attackers to reach internal services and arbitrary ports.

## Secure Mitigation
Upgrade to Marimo version 0.16.4 or later which adds authentication validation to the

## Vulnerable Code Pattern / Exploit Payload
```http
GET /mpl/1234 HTTP/1.1
Host: {{Hostname}}
```

