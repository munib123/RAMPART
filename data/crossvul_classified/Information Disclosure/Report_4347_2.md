# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in yaml
**Pair ID:** 4347_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```yaml
Lines 15-55 of the vulnerable file.

  sleuth:
    log.slf4j:
      enabled: true
      whitelisted-mdc-keys:
        - X-Amz-Cf-Id
    keys.http.headers: X-Amz-Cf-Id
    propagation-keys:
      - X-Amz-Cf-Id
    baggage:
      remote-fields: X-Amz-Cf-Id
      correlation-fields: X-Amz-Cf-Id

cloud:
  aws:
    region:
      auto: ${CLOUD.AWS.REGION.AUTO:false}
      static: ${CLOUD.AWS.REGION.STATIC:eu-west-1}
    stack:
      auto: ${CLOUD.AWS.STACK.AUTO:false}

management.endpoints.enabled-by-default: false

server:
  error.whitelabel.enabled: true
  compression:
    enabled: true
    mime-types:
      - application/json
      - application/xml
      - text/plain
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,13 @@
     stack:
       auto: ${CLOUD.AWS.STACK.AUTO:false}
 
-management.endpoints.enabled-by-default: false
+management:
+  endpoints.enabled-by-default: false
+  metrics:
+    export:
+      cloudwatch:
+        namespace: dpppt
+        batch-size: 20
 
 server:
   error.whitelabel.enabled: true
@@ -62,8 +68,13 @@
     com.amazonaws: error
     org.dpppt.backend.sdk.data.gaen.fakekeyservice: info
     org.dpppt.backend.sdk.ws.radarcovid: debug
+    org.dpppt.backend.sdk.ws.radarcovid.annotation: info
+    org.dpppt.backend.sdk.ws.radarcovid.config: info
     org.dpppt.backend.sdk.ws.security.gaen: debug
     org.dpppt: info
+    com.zaxxer.hikari.pool.HikariPool: debug
+    com.zaxxer.hikari.HikariConfig: debug
+    com.zaxxer.hikari: debug
   pattern:
     console: '[%-5level] [%X{X-B3-TraceId:-},%X{X-Amz-Cf-Id:-}] - %c{1} - %msg%n'
 
@@ -138,5 +149,7 @@
       enabled: ${RESPONSE_RETENTION_ENABLED:false}
       time:
         exposed: ${RESPONSE_RETENTION_TIME_EXPOSED:1000} # milliseconds
+        exposednextday: ${RESPONSE_RETENTION_TIME_EXPOSEDNEXTDAY:1000} # milliseconds
+
   log:
     enabled: ${LOGGABLE_ENABLED:false}
```
