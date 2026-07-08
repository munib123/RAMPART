# Vulnerability: Alibaba Metadata Service Check
**Classification:** CWE-441
**Source:** Nuclei Template (`metadata-alibaba.yaml`)

## Description
The Alibaba host is configured as a proxy which allows access to the metadata service. This could allow significant access to the host/infrastructure.

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{hostval}}/{{path}} HTTP/1.1
Host: {{hostval}}
```

