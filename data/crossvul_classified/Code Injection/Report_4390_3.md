# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4390_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4390_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-34 of the vulnerable file.

package com.browserup.bup.rest.validation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import javax.ws.rs.core.Context;

import com.browserup.bup.proxy.ProxyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { PortWithExistingProxyConstraint.PortWithExistingProxyConstraintValidator.class })
public @interface PortWithExistingProxyConstraint {

  String message() default "";

  String paramName() default "port";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  class PortWithExistingProxyConstraintValidator
      implements ConstraintValidator<PortWithExistingProxyConstraint, Integer> {
    private static final Logger LOG = LoggerFactory.getLogger(PortWithExistingProxyConstraintValidator.class);
    private static final String PARAM_NAME = "proxy port";

    private final ProxyManager proxyManager;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 
 import com.browserup.bup.proxy.ProxyManager;
 
+import com.browserup.bup.rest.validation.util.MessageSanitizer;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
@@ -47,7 +48,8 @@
         return true;
       }
 
-      String errorMessage = String.format("No proxy server found for specified port %d", value);
+      String escapedValue = MessageSanitizer.escape(value.toString());
+      String errorMessage = String.format("No proxy server found for specified port %s", escapedValue);
       LOG.warn(errorMessage);
 
       context.buildConstraintViolationWithTemplate(errorMessage).addPropertyNode(PARAM_NAME).addConstraintViolation();
```
