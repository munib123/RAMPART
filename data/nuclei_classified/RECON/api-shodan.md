# Vulnerability: Shodan API Test
**Classification:** RECON
**Source:** Nuclei Template (`api-shodan.yaml`)

## Description
Shodan is a search engine that lets users search for various types of servers connected to the internet using a variety of filters.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.shodan.io/api-info?key={{token}}
```

