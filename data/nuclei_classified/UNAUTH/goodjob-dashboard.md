# Vulnerability: goodjob-dashboard
**Classification:** UNAUTH
**Source:** Nuclei Template (`goodjob-dashboard.yaml`)

## Description
Rails GoodJob Dashboard panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jobs
GET {{BaseURL}}/good_job/jobs
```

