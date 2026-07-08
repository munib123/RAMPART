# Vulnerability: MapMyTracks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mapmytracks.yaml`)

## Description
MapMyTracks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mapmytracks.com/{{user}}
```

