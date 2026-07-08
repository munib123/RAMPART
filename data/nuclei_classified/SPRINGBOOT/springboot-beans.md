# Vulnerability: Detect Springboot Beans Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-beans.yaml`)

## Description
Displays a complete list of all the Spring beans in the application

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/beans
GET {{BaseURL}}/actuator/beans
```

