# Vulnerability: Opto 22 groov - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`opto22-groov-panel.yaml`)

## Description
Opto 22 groov is an IIoT and industrial automation platform providing browser-based
HMI and edge computing capabilities. The groov View and groov Admin interfaces allow
control of industrial devices and data acquisition systems. Exposed instances may
provide unauthenticated access to industrial control panels.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

