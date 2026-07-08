# Vulnerability: VTScada - Internet Client Panel
**Classification:** PANEL
**Source:** Nuclei Template (`vtscada-panel.yaml`)

## Description
VTScada (by Trihedral Engineering) is a SCADA platform used in water/
wastewater, oil and gas, and utilities. The Internet Client feature exposes
a browser-based view of process data, and is commonly deployed by municipal
water systems across North America.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

