# Vulnerability: Abstract Api Timezone Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-timezone.yaml`)

## Description
Quickly and easily get the time and date of a location or IP address, or convert the time and date of one timezone into another

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://timezone.abstractapi.com/v1/current_time/?api_key={{token}}&location=Oxford,%20United%20Kingdom
```

