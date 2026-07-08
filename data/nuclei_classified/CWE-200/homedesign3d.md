# Vulnerability: HomeDesign3D User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`homedesign3d.yaml`)

## Description
HomeDesign3D user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://en.homedesign3d.net/user/{{user}}
```

