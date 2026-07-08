# Vulnerability: Minecraft List User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`minecraft-list.yaml`)

## Description
Minecraft List user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://minecraftlist.com/players/{{user}}
```

