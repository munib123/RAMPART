# Vulnerability: AWS S3 keys Leak
**Classification:** AWS
**Source:** Nuclei Template (`wpconfig-aws-keys.yaml`)

## Description
AWS S3 keys are exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-config.php-backup
GET {{BaseURL}}/%c0
```

