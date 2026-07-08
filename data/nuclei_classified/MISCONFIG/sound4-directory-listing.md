# Vulnerability: SOUND4 Impact/Pulse/First/Eco <=2.x - Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sound4-directory-listing.yaml`)

## Description
The application is vulnerable to sensitive directory indexing / information disclosure vulnerability. An unauthenticated attacker can visit the log directory and disclose the server's log files containing sensitive and system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/log/
```

