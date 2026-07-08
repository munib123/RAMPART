# Vulnerability: Hazelcast Management Center - Configuration Exposure
**Classification:** CWE-306
**Source:** Nuclei Template (`hazelcast-management-exposure.yaml`)

## Description
Detected poor architectural configurations or unsecured REST API endpoints in Hazelcast by checking the cluster endpoint, which exposes internal member IPs, UUIDs, and version information.

## Secure Mitigation
Disable the Hazelcast REST API if not required. If its use is necessary, restrict network exposure, enable authentication mechanisms, limit access through firewall rules, and allow only trusted hosts to access the service.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hazelcast/rest/cluster
```

