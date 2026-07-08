# Vulnerability: Deimos C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`deimos-c2.yaml`)

## Description
DeimosC2 is a post-exploitation Command & Control (C2) tool that leverages multiple communication methods in order to control machines that have been compromised. DeimosC2 server and agents works on, and has been tested on, Windows, Darwin, and Linux.It is entirely written in Golang with a front end written in Vue.js.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

