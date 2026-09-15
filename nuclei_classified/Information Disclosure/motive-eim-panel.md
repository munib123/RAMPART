# Nuclei Template: Motive eSIM Secure Connect Panel - Exposure Detection
**Template ID:** motive-eim-panel
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`motive-eim-panel.yaml`)

## Vulnerability Information & PoC

## Description
Detects exposed Motive eSIM Secure Connect (EIM) panels used for managing eSIM/iSIM provisioning. Public access to these interfaces may allow attackers to view or interact with sensitive operations such as EID management and bulk provisioning, leading to information disclosure or unauthorized control over IoT/mobile connectivity services.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/eIMConfiguration
GET {{BaseURL}}/eid-management
GET {{BaseURL}}/eid-management-new
GET {{BaseURL}}/bulk-profile-operation
```

## References
- https://motive.com/eim
