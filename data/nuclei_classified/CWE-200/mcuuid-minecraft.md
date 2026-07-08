# Vulnerability: MCUUID (Minecraft) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mcuuid-minecraft.yaml`)

## Description
MCUUID (Minecraft) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://playerdb.co/api/player/minecraft/{{user}}
```

