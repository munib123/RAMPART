# Vulnerability: LocalStack - Detect
**Classification:** LOCALSTACK
**Source:** Nuclei Template (`localstack-detect.yaml`)

## Description
LocalStack (localstack.cloud / github.com/localstack/localstack) is a local AWS cloud-service emulator widely used in development and CI. It typically listens on TCP 4566 and exposes an unauthenticated /_localstack/health endpoint that lists every emulated service and its enabled state. An exposed LocalStack on a non-loopback interface gives an attacker a fully-functional fake AWS account, including S3, SQS, IAM, SecretsManager and Lambda execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_localstack/health
```

