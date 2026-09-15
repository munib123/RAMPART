# Nuclei Template: Oracle Cloud Metadata Service Check
**Template ID:** metadata-service-oracle
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`metadata-oracle.yaml`)

## Vulnerability Information & PoC

## Description
The Oracle cloud host is configured as a proxy which allows access to the instance metadata IMDSv1 service. This could allow significant access to the host/infrastructure.

## Steps to reproduce / Exploit Payload
```http
GET http://{{hostval}}/opc/v1/instance HTTP/1.1
Host: {{hostval}}
Metadata: true
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## References
- https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm
- https://blog.projectdiscovery.io/abusing-reverse-proxies-metadata/
- https://www.mcafee.com/blogs/enterprise/cloud-security/how-an-attacker-could-use-instance-metadata-to-breach-your-app-in-aws/
