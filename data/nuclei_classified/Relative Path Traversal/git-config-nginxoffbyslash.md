# Nuclei Template: Nginx - Git Configuration Exposure
**Template ID:** git-config-nginxoffbyslash
**Vulnerability Class:** Relative Path Traversal
**Severity:** Medium
**CWE:** CWE-23
**Source:** Nuclei Template (`git-config-nginxoffbyslash.yaml`)

## Vulnerability Information & PoC

## Description
Nginx is vulnerable to git configuration exposure.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://beaglesecurity.com/blog/vulnerability/nginx-off-by-slash-exposes-git-config.html
- https://twitter.com/Random_Robbie/status/1262676628167110656
- https://github.com/PortSwigger/nginx-alias-traversal/blob/master/off-by-slash.py
