# Vulnerability: AWS CodeBuild Build Spec - Exposure
**Classification:** AWS
**Source:** Nuclei Template (`aws-buildspec-exposure.yaml`)

## Description
Detected the presence of the AWS CodeBuild buildspec.yml file. This file contains build commands and settings that may disclose sensitive information about the application's build process and infrastructure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/buildspec.yml
GET {{BaseURL}}/buildspec.yaml
```

