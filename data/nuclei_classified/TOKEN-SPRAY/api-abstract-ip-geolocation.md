# Vulnerability: Abstract Api IP Geolocation Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-ip-geolocation.yaml`)

## Description
Get the location of any IP with a world-class APIserving city, region, country and lat/long data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ipgeolocation.abstractapi.com/v1/?api_key={{token}}&ip_address=92.184.105.98
```

