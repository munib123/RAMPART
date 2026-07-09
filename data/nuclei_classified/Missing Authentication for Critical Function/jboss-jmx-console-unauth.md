# Nuclei Template: JBoss JMX Console - Unauthenticated Access
**Template ID:** jboss-jmx-console-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`jboss-jmx-console-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Detected JBoss JMX Console was accessible without authentication. The exposed console provided complete access to all MBeans, including MainDeployer, which enabled arbitrary WAR file deployment, leading to remote code execution. Attackers could view the entire MBean tree, deploy malicious applications, and invoke administrative operations without valid credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jmx-console/HtmlAdaptor?action=displayMBeans
```

## References
- https://developer.jboss.org/wiki/SecureTheJmxConsole
- https://www.invicti.com/web-application-vulnerabilities/jboss-jmx-console-unrestricted-access
