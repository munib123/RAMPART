# Vulnerability: Fronius Datalogger Web - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`fronius-datalogger-web-panel.yaml`)

## Description
Fronius Datalogger Web is a web interface for Fronius solar inverter data loggers, providing real-time monitoring and configuration of photovoltaic systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

