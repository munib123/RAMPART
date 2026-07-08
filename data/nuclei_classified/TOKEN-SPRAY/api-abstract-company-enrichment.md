# Vulnerability: Abstract Api Company Enrichment Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-company-enrichment.yaml`)

## Description
Enrich any domain or email with accurate company data, including headcount, location and industry.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://companyenrichment.abstractapi.com/v1/?api_key={{token}}&domain=airbnb.com
```

