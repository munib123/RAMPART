# Vulnerability: GitLab CI YAML - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`gitlab-ci-yml.yaml`)

## Description
The gitlab-ci.yml file, used for configuring CI/CD pipelines in GitLab, has been found exposed. This file contains crucial details about the build, test, and deployment processes, and may include sensitive information such as API keys, tokens, environment variables, and other credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gitlab-ci.yml
GET {{BaseURL}}/gitlab-ci.yml
GET {{BaseURL}}/.gitlab-ci/variables.yml
```

