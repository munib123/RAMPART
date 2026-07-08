# Vulnerability: Node ecstatic Directory Listing
**Classification:** NODE
**Source:** Nuclei Template (`node-ecstatic-listing.yaml`)

## Description
Directiory listing enabled in Node ecstatic.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/img/
```

