# Nuclei Template: Apache Airflow Configuration Page - Detect
**Template ID:** airflow-configuration-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`airflow-configuration-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Apache Airflow configuration page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/airflow.cfg
```

