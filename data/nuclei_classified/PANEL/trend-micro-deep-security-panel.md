# Vulnerability: Trend Micro Deep Security Manager - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`trend-micro-deep-security-panel.yaml`)

## Description
Trend Micro Deep Security Manager is an enterprise server security platform that provides intrusion detection, anti-malware, firewall, and integrity monitoring capabilities for physical, virtual, and cloud environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

