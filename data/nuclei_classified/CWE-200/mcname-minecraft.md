# Vulnerability: MCName (Minecraft) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mcname-minecraft.yaml`)

## Description
MCName (Minecraft) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mcname.info/en/search?q={{user}}
```

