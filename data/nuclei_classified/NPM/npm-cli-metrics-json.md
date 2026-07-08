# Vulnerability: NPM Anonymous CLI Metrics Json
**Classification:** NPM
**Source:** Nuclei Template (`npm-cli-metrics-json.yaml`)

## Description
anonymous-cli-metrics.json internal file in NPM is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/anonymous-cli-metrics.json
GET {{BaseURL}}/.npm/anonymous-cli-metrics.json
```

