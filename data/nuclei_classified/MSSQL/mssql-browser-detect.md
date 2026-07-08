# Vulnerability: MS-SQL Browser Service - Detect
**Classification:** MSSQL
**Source:** Nuclei Template (`mssql-browser-detect.yaml`)

## Description
Detects Microsoft SQL Server Browser service on UDP port 1434 by triggering an SVR_RESP response with a 0x02 probe.Extracts instance details such as ServerName, InstanceName, SQL version, clustering status, and TCP port information.

