# Vulnerability: Multi-function Printer - Unauthorized Access
**Classification:** NETWORK
**Source:** Nuclei Template (`mfp-unauth-exposure.yaml`)

## Description
Unauthorized access to MFP (Multi-function printer) using eSCL protocol allows attackers to scan documents left physically in the printer and send them to an arbitrary location. Furthermore, exposure of this endpoint allows attackers to gather information about the printer, serial number, model, and possibly pull documents scanned by legitimate users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/eSCL/ScannerCapabilities
```

