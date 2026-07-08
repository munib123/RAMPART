# Vulnerability: Nokia Nuage Networks VSP - Dashboard Panel
**Classification:** PANEL
**Source:** Nuclei Template (`nuage-networks-vsp-panel.yaml`)

## Description
Nokia Nuage Networks VSP (Virtualized Services Platform) is a software-defined
networking platform for enterprise and service provider SDN/NFV deployments.
The web dashboard is exposed on ports 8443, 9090, or 11443.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

