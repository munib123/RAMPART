# Vulnerability: Google GCP Metadata Service Check
**Classification:** CWE-441
**Source:** Nuclei Template (`metadata-google.yaml`)

## Description
The Google cloud (GCP) host is configured as a proxy which allows access to the instance metadata service. This could allow significant access to the host/infrastructure.

## Secure Mitigation
Disable the proxy or restrict configuration to only allow access to approved hosts/ports. Upgrade to IMDSv2 if possible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{hostval}}/computeMetadata/v1/project/ HTTP/1.1
Host: {{hostval}}
Metadata-Flavor: Google
```

