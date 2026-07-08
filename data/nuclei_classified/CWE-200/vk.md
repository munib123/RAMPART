# Vulnerability: VK User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vk.yaml`)

## Description
VK user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vk.com/{{user}}
```

