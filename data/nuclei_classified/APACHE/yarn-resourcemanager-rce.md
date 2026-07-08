# Vulnerability: Apache Hadoop YARN ResourceManager - Remote Code Execution
**Classification:** APACHE
**Source:** Nuclei Template (`yarn-resourcemanager-rce.yaml`)

## Description
Apache Hadoop YARN ResourceManager is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/ws/v1/cluster/apps/new-application
```

