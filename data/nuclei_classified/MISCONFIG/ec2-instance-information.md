# Vulnerability: EC2 Instance Information
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ec2-instance-information.yaml`)

## Description
EC2 Instance information is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

