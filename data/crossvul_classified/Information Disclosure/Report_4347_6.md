# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4347_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
package org.dpppt.backend.sdk.ws.radarcovid.config;

import java.util.Arrays;

import org.apache.commons.lang3.math.NumberUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.dpppt.backend.sdk.ws.radarcovid.annotation.ResponseRetention;
import org.dpppt.backend.sdk.ws.radarcovid.exception.RadarCovidServerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * Aspect in charge of controlling the minimum response time of a service.
 */
@Configuration
@ConditionalOnProperty(name = "application.response.retention.enabled", havingValue = "true", matchIfMissing = true)
public class ResponseRetentionAspectConfiguration {

	private static final Logger log = LoggerFactory.getLogger("org.dpppt.backend.sdk.ws.radarcovid.annotation.ResponseRetention");
	
	@Autowired
	private Environment environment;
	
    @Aspect
    @Component
    public class ControllerTimeResponseControlAspect {

        @Pointcut("@annotation(responseRetention)")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 import org.springframework.beans.factory.annotation.Autowired;
 import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
 import org.springframework.context.annotation.Configuration;
+import org.springframework.core.annotation.Order;
 import org.springframework.core.env.Environment;
 import org.springframework.http.HttpStatus;
 import org.springframework.stereotype.Component;
@@ -40,6 +41,7 @@
 	private Environment environment;
 	
     @Aspect
+    @Order(0)
     @Component
     public class ControllerTimeResponseControlAspect {
 
```
