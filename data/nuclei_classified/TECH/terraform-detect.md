# Vulnerability: Detect Terraform Provider
**Classification:** TECH
**Source:** Nuclei Template (`terraform-detect.yaml`)

## Description
Write Infrastructure as Code - https://www.terraform.io/

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/provider.tf
```

