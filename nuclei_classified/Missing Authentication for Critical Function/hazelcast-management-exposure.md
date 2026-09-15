# Nuclei Template: Hazelcast Management Center - Configuration Exposure
**Template ID:** hazelcast-management-exposure
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** Medium
**CWE:** CWE-306
**Source:** Nuclei Template (`hazelcast-management-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected poor architectural configurations or unsecured REST API endpoints in Hazelcast by checking the cluster endpoint, which exposes internal member IPs, UUIDs, and version information.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/hazelcast/rest/cluster
```

## Remediation
Disable the Hazelcast REST API if not required. If its use is necessary, restrict network exposure, enable authentication mechanisms, limit access through firewall rules, and allow only trusted hosts to access the service.

## References
- https://docs.hazelcast.com/imdg/latest/management-center/rest-api
