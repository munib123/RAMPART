# Nuclei Template: IoTaWatt Configuration App Exposure
**Template ID:** iotawatt-app-exposure
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`iotawatt-app-exposure.yaml`)

## Vulnerability Information & PoC

## Description
An IoTaWatt configuration app was discovered. Unauthenticated access to an IoTaWatt energy monitor could give a malicious attacker the means to upload to any of several third-party energy websites/database.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://docs.iotawatt.com/en/master/passConfig.html
