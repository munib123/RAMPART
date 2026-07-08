# Vulnerability: OpenVPN Monitor - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openvpn-monitor.yaml`)

## Description
openvpn-monitor was discovered. OpenVPN Monitor is a simple python program to generate html that displays the status of an OpenVPN server, including all its current connections.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/openvpn-monitor/
```

