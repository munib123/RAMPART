# Vulnerability: PTC ThingWorx - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`ptc-thingworx-panel.yaml`)

## Description
PTC ThingWorx is an Industrial IoT (IIoT) platform for building and deploying
connected industrial applications, machine monitoring, and remote service solutions.
Exposed instances may provide unauthenticated access to IIoT dashboards and
connected device management interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

