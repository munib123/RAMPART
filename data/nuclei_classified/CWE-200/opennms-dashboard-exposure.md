# Vulnerability: OpenNMS Dashboard - Exposure Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`opennms-dashboard-exposure.yaml`)

## Description
OpenNMS Dashboard exposure was detected. OpenNMS is an enterprise-grade network monitoring platform. Exposed dashboards may reveal sensitive network infrastructure information, monitoring data, alarms, and potentially allow unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opennms/index.jsp
GET {{BaseURL}}/opennms/dashboard.jsp
GET {{BaseURL}}/opennms/
```

