# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4347_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1-40 of the vulnerable file.

/*
 * Copyright (c) 2020 Gobierno de España
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.dpppt.backend.sdk.ws.radarcovid.config;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * Aspecto encargado de trazar la información de los servicios implementados.
 */
@Configuration
@ConditionalOnProperty(name = "application.log.enabled", havingValue = "true", matchIfMissing = true)
public class MethodLoggerAspectConfiguration {

    private static final Logger log = LoggerFactory.getLogger("org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable");

    @Aspect
    @Component
    public class MethodLoggerAspect {
        @Before("execution(@org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable * *..business.impl..*(..))")
        public void logBefore(JoinPoint joinPoint) {
            if (log.isDebugEnabled()) {
                log.debug("   ************************* INIT SERVICE ******************************");
                log.debug("   Service : Entering in Method : {}", joinPoint.getSignature().getDeclaringTypeName());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 import org.slf4j.LoggerFactory;
 import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
 import org.springframework.context.annotation.Configuration;
+import org.springframework.core.annotation.Order;
 import org.springframework.stereotype.Component;
 
 import java.util.Arrays;
@@ -31,6 +32,7 @@
     private static final Logger log = LoggerFactory.getLogger("org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable");
 
     @Aspect
+    @Order(2)
     @Component
     public class MethodLoggerAspect {
         @Before("execution(@org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable * *..business.impl..*(..))")
```
