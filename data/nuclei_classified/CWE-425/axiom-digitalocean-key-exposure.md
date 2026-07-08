# Vulnerability: DigitalOcean Key Exposure via Axiom
**Classification:** CWE-425
**Source:** Nuclei Template (`axiom-digitalocean-key-exposure.yaml`)

## Description
Axiom is a dynamic infrastructure framework to efficiently work with multi-cloud environments.

## Secure Mitigation
Restrict access to the do.json file or upgrade to a newer version of Axiom

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.axiom/accounts/do.json
```

