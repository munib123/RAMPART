# Vulnerability: NextcloudPi Dashboard - Exposed
**Classification:** NEXTCLOUD
**Source:** Nuclei Template (`nextcloudpi-dashboard.yaml`)

## Description
Detects exposed NextcloudPi dashboard instances. NextcloudPi dashboard is typically accessible on port 4443 and should not be exposed to the internet as it provides administrative access to the NextcloudPi instance.

## Secure Mitigation
Restrict access to the NextcloudPi dashboard to trusted IP addresses only. Use a VPN or firewall rules to limit access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?app=config
```

