# Vulnerability: AWS Elastic Beanstalk Dockerrun.aws.json - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`dockerrun-aws-json-exposure.yaml`)

## Description
Detected AWS Elastic Beanstalk Dockerrun.aws.json configuration file was publicly accessible, potentially revealing Docker container definitions, image names, hostnames, port mappings, and infrastructure details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Dockerrun.aws.json
GET {{BaseURL}}/static/Dockerrun.aws.json
```

