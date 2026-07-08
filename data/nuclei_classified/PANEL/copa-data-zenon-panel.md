# Vulnerability: Copa-Data zenon - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`copa-data-zenon-panel.yaml`)

## Description
Copa-Data zenon is an industrial automation platform used in manufacturing,
energy, and infrastructure. The zenon Web Server and Smart Server expose a
browser-based HMI interface for remote monitoring and control of SCADA processes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

