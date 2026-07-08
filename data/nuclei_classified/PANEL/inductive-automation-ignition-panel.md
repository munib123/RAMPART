# Vulnerability: Inductive Automation Ignition - Gateway Panel
**Classification:** PANEL
**Source:** Nuclei Template (`inductive-automation-ignition-panel.yaml`)

## Description
Inductive Automation Ignition is a widely-deployed industrial SCADA/HMI
platform used in manufacturing, utilities, and process industries. The
Ignition Gateway web interface provides access to project management,
OPC-UA tag browsing, and system configuration. Exposed gateways may
allow unauthenticated access to project lists and system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

