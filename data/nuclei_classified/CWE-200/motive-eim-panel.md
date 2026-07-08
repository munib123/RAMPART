# Vulnerability: Motive eSIM Secure Connect Panel - Exposure Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`motive-eim-panel.yaml`)

## Description
Detects exposed Motive eSIM Secure Connect (EIM) panels used for managing eSIM/iSIM provisioning. Public access to these interfaces may allow attackers to view or interact with sensitive operations such as EID management and bulk provisioning, leading to information disclosure or unauthorized control over IoT/mobile connectivity services.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/eIMConfiguration
GET {{BaseURL}}/eid-management
GET {{BaseURL}}/eid-management-new
GET {{BaseURL}}/bulk-profile-operation
```

