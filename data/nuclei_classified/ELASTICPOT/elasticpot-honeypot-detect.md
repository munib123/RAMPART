# Vulnerability: ElasticPot Honeypot - Detect
**Classification:** ELASTICPOT
**Source:** Nuclei Template (`elasticpot-honeypot-detect.yaml`)

## Description
A ElasticPot (ElasticSearch) honeypot has been identified.
The response to a '_cluster/settings' request differs from real installations, signaling a possible deceptive setup.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_cluster/settings
```

