# Vulnerability: Europeana API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-europeana.yaml`)

## Description
European Museum and Galleries content

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.europeana.eu/record/v2/search.json?wskey={{token}}&query=*&rows=0&profile=facets
```

