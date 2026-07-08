# Vulnerability: NextcloudPi Login - Panel
**Classification:** NEXTCLOUD
**Source:** Nuclei Template (`nextcloudpi-panel.yaml`)

## Description
Detects the presence of a NextcloudPi login page. NextcloudPi is a ready-to-use Nextcloud instance for Raspberry Pi.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/login
```

