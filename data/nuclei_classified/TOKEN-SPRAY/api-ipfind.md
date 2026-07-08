# Vulnerability: IPFind API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-ipfind.yaml`)

## Description
Geographic location of an IP address or any domain name along with some other useful information

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.ipfind.io/api/iplocation?apikey={{token}}
```

