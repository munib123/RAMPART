# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in yaml
**Pair ID:** 4347_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```yaml
Lines 45-85 of the vulnerable file.

      - text/xml
  http2:
    enabled: true
  port: ${SERVER_PORT:8080}

logging:
  group:
    cleanup:
      - org.dpppt.backend.sdk.ws.config.WSSediaConfig
      - org.dpppt.backend.sdk.data.gaen.JDBCGAENDataServiceImpl
      - org.dpppt.backend.sdk.data.JDBCDPPPTDataServiceImpl
      - org.dpppt.backend.sdk.data.JDBCRedeemDataServiceImpl
  level:
    root: info
    cleanup: warn
    org.springframework: warn
    org.flywaydb: warn
    com.amazonaws: error
    org.dpppt.backend.sdk.data.gaen.fakekeyservice: info
    org.dpppt.backend.sdk.ws.radarcovid: debug
    org.dpppt.backend.sdk.ws.security.gaen: debug
    org.dpppt: info
  pattern:
    console: '[%-5level] [%X{X-B3-TraceId:-},%X{X-Amz-Cf-Id:-}] - %c{1} - %msg%n'

#-------------------------------------------------------------------------------
# JDBC Config
#-------------------------------------------------------------------------------
datasource:
  url: ${DATASOURCE_URL:jdbc:postgresql://localhost:5432/dpppt}
  username: ${DATASOURCE_USER:dpppt}
  password: ${DATASOURCE_PASS:dpppt}
  schema: ${DATASOURCE_SCHEMA:dpppt}
  driverClassName: org.postgresql.ds.PGSimpleDataSource
  failFast: ${DATASOURCE_FAIL_FAST:true}
  maximumPoolSize: ${DATASOURCE_MAX_POOL_SIZE:5}
  maxLifetime: ${DATASOURCE_MAX_LIFE_TIME:1700000}
  idleTimeout: ${DATASOURCE_IDLE_TIMEOUT:600000}
  connectionTimeout: ${DATASOURCE_CONNECTION_TIMEOUT:30000}
  flyway.load: ${DATASOURCE_FLYWAY_LOAD:true}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,8 @@
     com.amazonaws: error
     org.dpppt.backend.sdk.data.gaen.fakekeyservice: info
     org.dpppt.backend.sdk.ws.radarcovid: debug
+    org.dpppt.backend.sdk.ws.radarcovid.config: info
+    org.dpppt.backend.sdk.ws.radarcovid.annotation: info
     org.dpppt.backend.sdk.ws.security.gaen: debug
     org.dpppt: info
   pattern:
@@ -138,5 +140,7 @@
       enabled: ${RESPONSE_RETENTION_ENABLED:true}
       time:
         exposed: ${RESPONSE_RETENTION_TIME_EXPOSED:1000} # milliseconds
+        exposednextday: ${RESPONSE_RETENTION_TIME_EXPOSEDNEXTDAY:1000} # milliseconds
+
   log:
     enabled: ${LOGGABLE_ENABLED:true}
```
