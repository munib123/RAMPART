# Vulnerability: Detect Jenkins in Debug Mode with Stack Traces Enabled
**Classification:** JENKINS
**Source:** Nuclei Template (`jenkins-stack-trace.yaml`)

## Description
Module identified that the affected host is running an instance of Jenkins in debug mode, as a result stack traces are enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adjuncts/3a890183/
```

