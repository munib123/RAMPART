# Vulnerability: Shell In A Box - Detect
**Classification:** SHELL
**Source:** Nuclei Template (`shell-box.yaml`)

## Description
Shell In A Box implements a web server that can export arbitrary command line tools to a web based terminal emulator

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

