# Nuclei Template: AWS Elastic Beanstalk Dockerrun.aws.json - Exposure
**Template ID:** dockerrun-aws-json-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`dockerrun-aws-json-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected AWS Elastic Beanstalk Dockerrun.aws.json configuration file was publicly accessible, potentially revealing Docker container definitions, image names, hostnames, port mappings, and infrastructure details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Dockerrun.aws.json
GET {{BaseURL}}/static/Dockerrun.aws.json
```

## References
- https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_v2config.html
