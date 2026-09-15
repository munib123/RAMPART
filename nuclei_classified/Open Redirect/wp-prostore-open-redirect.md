# Nuclei Template: WordPress ProStore <1.1.3 - Open Redirect
**Template ID:** wp-prostore-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Low
**Source:** Nuclei Template (`wp-prostore-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress ProStore theme before 1.1.3 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/prostore/go.php?https://interact.sh/
```

## References
- https://wpscan.com/vulnerability/2e0f8b7f-96eb-443c-a553-550e42ec67dc
