# Vulnerability: WordPress Plugin dzs zoomsounds
**Classification:** WORDPRESS
**Source:** Nuclei Template (`dzs-zoomsounds-listing.yaml`)

## Description
Searches for sensitive directories present in the dzs-zoomsounds plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/dzs-zoomsounds/
```

