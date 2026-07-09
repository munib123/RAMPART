# Nuclei Template: Amazon AWS Metadata Service Check
**Template ID:** metadata-service-aws
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`metadata-aws.yaml`)

## Vulnerability Information & PoC

## Description
The host is configured as a proxy which allows access to the metadata provided by a cloud provider such as AWS or OVH. This could allow significant access to the host/infrastructure.

## Steps to reproduce / Exploit Payload
```http
GET http://{{hostval}}/latest/meta-data/ HTTP/1.1
Host: {{hostval}}
```

## Remediation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## References
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- https://blog.projectdiscovery.io/abusing-reverse-proxies-metadata/
- https://www.mcafee.com/blogs/enterprise/cloud-security/how-an-attacker-could-use-instance-metadata-to-breach-your-app-in-aws/
- https://twitter.com/Random_Robbie/status/1268186743657947137
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#
