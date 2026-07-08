# Vulnerability: Visnesscard User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`visnesscard.yaml`)

## Description
Visnesscard user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://my.visnesscard.com/Home/GetCard/{{user}}
```

