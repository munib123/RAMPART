# Vulnerability: Spring Boot Actuator - Heap Dump Detection
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-heapdump.yaml`)

## Description
A Spring Boot Actuator heap dump was detected. A heap dump is a snapshot of JVM memory, which could expose environment variables and HTTP requests.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /{{str}} HTTP/1.1
Host: {{Hostname}}

GET /{{path}} HTTP/1.1
Host: {{Hostname}}
```

