# Vulnerability: Azure Instrumentation Key - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`azure-instrumentation-key-exposure.yaml`)

## Description
Detected exposed Azure Application Insights Instrumentation Keys (classic ikey format) in HTTP responses, which allowed anyone to send telemetry data and, in some older configurations, could enable read access via undocumented or legacy APIs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/appsettings.json
```

