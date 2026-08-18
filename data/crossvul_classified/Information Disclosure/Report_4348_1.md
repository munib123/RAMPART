# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in yaml
**Pair ID:** 4348_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4348_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```yaml
Lines 116-135 of the vulnerable file.

springdoc:
  paths-to-match: /v1/gaen/**
  #packagesToScan: org.dpppt.backend.sdk
  api-docs:
    path: /openapi/api-docs
    enabled: ${OPENAPI_ENABLED:true}
  swagger-ui:
    path: /openapi/ui
    enabled: ${OPENAPI_ENABLED:true}

application:
  openapi:
    title: DP3T API
    description: DP3T API
    version: '@project.version@'
    terms-of-service: http://sedia.com/
  endpoint:
    validation:
      url: ${TAN_VALIDATION_URL:}
      enabled: ${TAN_VALIDATION_ENABLED:false}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,3 +133,10 @@
     validation:
       url: ${TAN_VALIDATION_URL:}
       enabled: ${TAN_VALIDATION_ENABLED:false}
+  response:
+    retention:
+      enabled: ${RESPONSE_RETENTION_ENABLED:false}
+      time:
+        exposed: ${RESPONSE_RETENTION_TIME_EXPOSED:1000} # milliseconds
+  log:
+    enabled: ${LOGGABLE_ENABLED:false}
```
