# Vulnerability: Microsoft SCCM - Anonymous Distribution Point Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`anonymous-distribution-point-sccm.yaml`)

## Description
Microsoft System Center Configuration Manager (SCCM) can be configured to allow anonymous access to its distribution points.This can lead to sensitive data exposure and information gathering by unauthorized users.This misconfiguration is exploitable only via HTTP.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SMS_DP_SMSPKG$/Datalib
GET {{BaseURL}}:80/SMS_DP_SMSPKG$/Datalib
```

