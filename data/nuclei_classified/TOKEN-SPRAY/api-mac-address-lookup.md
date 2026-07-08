# Vulnerability: MAC Address Lookup API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-mac-address-lookup.yaml`)

## Description
Retrieve vendor details and other information regarding a given MAC address or an OUI

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.macaddress.io/v1?apiKey={{token}}&output=json&search=44:38:39:ff:ef:57
```

