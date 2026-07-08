# Vulnerability: Iomega LenovoEMC NAS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iomega-emc-shared-nas.yaml`)

## Description
Iomega LenovoEMC NAS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cp/Shares?user=&protocol=webaccess&v=2.3
```

