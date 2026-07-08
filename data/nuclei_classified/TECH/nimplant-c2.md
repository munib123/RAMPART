# Vulnerability: NimPlant C2 Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`nimplant-c2.yaml`)

## Description
NimPlant is an open source light first-stage C2 implant written in Nim and Python. It is designed to be used as a starting point for those who want to develop their own custom C2 implants. NimPlant is fully customizable and lightweight, making it easy to integrate into existing C2 frameworks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

