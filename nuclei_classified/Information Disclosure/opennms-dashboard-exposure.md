# Nuclei Template: OpenNMS Dashboard - Exposure Detection
**Template ID:** opennms-dashboard-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`opennms-dashboard-exposure.yaml`)

## Vulnerability Information & PoC

## Description
OpenNMS Dashboard exposure was detected. OpenNMS is an enterprise-grade network monitoring platform. Exposed dashboards may reveal sensitive network infrastructure information, monitoring data, alarms, and potentially allow unauthorized access.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/opennms/index.jsp
GET {{BaseURL}}/opennms/dashboard.jsp
GET {{BaseURL}}/opennms/
```

## References
- https://docs.opennms.com/horizon/35/operation/deep-dive/visualizations/dashboard.html
- https://docs.opennms.com/horizon/30/operation/user-management/introduction.html
- https://www.opennms.com/
