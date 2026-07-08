# Vulnerability: Twonky Server - Exposure
**Classification:** TWONKY
**Source:** Nuclei Template (`twonky-server-exposure.yaml`)

## Description
Twonky Server is a media server software that allows streaming of multimedia content over DLNA/UPnP protocols. When exposed to the internet or an untrusted network without proper authentication or access restrictions, it may allow unauthorized users to browse and access media files, interact with server settings, or gather sensitive network information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

