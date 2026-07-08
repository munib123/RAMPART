# Vulnerability: Spring Boot Actuator SBOM - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-sbom.yaml`)

## Description
Spring Boot Actuator SBOM endpoint was detected and is exposed without authentication. The endpoint returns a Software Bill of Materials (typically CycloneDX or SPDX JSON) listing every dependency and version shipped with the application, which lets an attacker enumerate the exact library inventory and trivially map it to known CVEs for targeted exploitation.

## Secure Mitigation
Disable the SBOM actuator endpoint in production or restrict it to internal use only. In application.properties set `management.endpoint.sbom.enabled=false`, or scope actuator exposure with `management.endpoints.web.exposure.include` to only the endpoints you actually need. Place all actuator endpoints behind authentication using Spring Security (e.g. require `ROLE_ACTUATOR`) and bind them to a separate, non-public management port via `management.server.port` / `management.server.address`.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sbom
GET {{BaseURL}}/actuator/sbom
GET {{BaseURL}}/sbom/application
GET {{BaseURL}}/actuator/sbom/application
```

