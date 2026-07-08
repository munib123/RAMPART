# Vulnerability: Umbraco Mini Profiler - Exposure
**Classification:** UMBRACO
**Source:** Nuclei Template (`umbraco-miniprofiler-exposure.yaml`)

## Description
Detected the exposure of the MiniProfiler debugging interface in Umbraco CMS. When exposed, it can reveal sensitive information including SQL queries, execution times, stack traces, and internal application details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mini-profiler-resources/results
GET {{BaseURL}}/umbraco/mini-profiler-resources/results
```

