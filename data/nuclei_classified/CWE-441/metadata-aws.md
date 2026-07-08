# Vulnerability: Amazon AWS Metadata Service Check
**Classification:** CWE-441
**Source:** Nuclei Template (`metadata-aws.yaml`)

## Description
The host is configured as a proxy which allows access to the metadata provided by a cloud provider such as AWS or OVH. This could allow significant access to the host/infrastructure.

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{hostval}}/latest/meta-data/ HTTP/1.1
Host: {{hostval}}
```

