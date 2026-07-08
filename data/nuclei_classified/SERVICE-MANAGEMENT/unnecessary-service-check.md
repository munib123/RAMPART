# Vulnerability: Unnecessary Service Removal Check
**Classification:** SERVICE-MANAGEMENT
**Source:** Nuclei Template (`unnecessary-service-check.yaml`)

## Description
Ensure that unnecessary services such as Alerter, Clipbook, Messenger, and Simple TCP/IP Services are not running. If enabled, these services can expose the system to security vulnerabilities.

## Secure Mitigation
To stop and disable these services, run:
> net stop [ServiceName]
> sc config [ServiceName] start= disabled

