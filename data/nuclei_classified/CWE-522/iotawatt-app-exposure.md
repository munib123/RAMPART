# Vulnerability: IoTaWatt Configuration App Exposure
**Classification:** CWE-522
**Source:** Nuclei Template (`iotawatt-app-exposure.yaml`)

## Description
An IoTaWatt configuration app was discovered. Unauthenticated access to an IoTaWatt energy monitor could give a malicious attacker the means to upload to any of several third-party energy websites/database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

