# Vulnerability: NetworksDB API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-networksdb.yaml`)

## Description
US Address Verification

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://networksdb.io/api/key HTTP/1.1
Host: networksdb.io
X-Api-Key: {{token}}
```

