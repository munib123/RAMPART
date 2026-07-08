# Vulnerability: OpenSCADA - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`openscada-panel.yaml`)

## Description
OpenSCADA is an open-source SCADA (Supervisory Control and Data Acquisition)
system. Exposed instances may provide access to industrial control interfaces
and operational technology (OT) data without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

