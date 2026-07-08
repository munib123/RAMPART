# Vulnerability: OpenRemote IoT Platform - Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`openremote-detect.yaml`)

## Description
Detects exposed OpenRemote IoT platform instances by checking login page titles, API endpoints, and specific OpenRemote UI artifacts. OpenRemote isan open-source IoT platform with a Keycloak-backed auth system.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
GET {{BaseURL}}/manager/
```

