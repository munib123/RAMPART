# Vulnerability: FUXA - SCADA/HMI Panel
**Classification:** PANEL
**Source:** Nuclei Template (`fuxa-scada-panel.yaml`)

## Description
FUXA is an open-source web-based SCADA/HMI platform built on Node.js.
It supports Modbus, OPC-UA, BACnet, MQTT, and Siemens S7 protocols and
is widely self-hosted for small industrial deployments. Instances are
frequently exposed to the internet without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

