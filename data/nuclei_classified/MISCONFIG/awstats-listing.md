# Vulnerability: AWStats Listing
**Classification:** MISCONFIG
**Source:** Nuclei Template (`awstats-listing.yaml`)

## Description
Searches for exposed awstats Internal Information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/awstats/data
```

