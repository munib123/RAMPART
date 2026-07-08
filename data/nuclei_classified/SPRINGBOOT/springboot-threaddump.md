# Vulnerability: Detect Springboot Thread Dump page
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-threaddump.yaml`)

## Description
The threaddump endpoint provides a thread dump from the application's JVM.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/threaddump
GET {{BaseURL}}/actuator/threaddump
```

