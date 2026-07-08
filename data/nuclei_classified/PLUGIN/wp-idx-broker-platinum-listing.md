# Vulnerability: WordPress Plugin Idx Broker Platinum Listing
**Classification:** PLUGIN
**Source:** Nuclei Template (`wp-idx-broker-platinum-listing.yaml`)

## Description
Searches for sensitive directories present in the idx-broker-platinum plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/idx-broker-platinum/
```

