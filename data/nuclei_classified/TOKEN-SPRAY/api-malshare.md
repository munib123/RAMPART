# Vulnerability: MalShare API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-malshare.yaml`)

## Description
Malware Archive / file sourcing

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.malshare.com/api.php?api_key={{token}}&action=getlist
```

