# Vulnerability: JBoss JMX Console - Unauthenticated Access
**Classification:** CWE-306
**Source:** Nuclei Template (`jboss-jmx-console-unauth.yaml`)

## Description
Detected JBoss JMX Console was accessible without authentication. The exposed console provided complete access to all MBeans, including MainDeployer, which enabled arbitrary WAR file deployment, leading to remote code execution. Attackers could view the entire MBean tree, deploy malicious applications, and invoke administrative operations without valid credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jmx-console/HtmlAdaptor?action=displayMBeans
```

