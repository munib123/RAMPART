# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4390_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4390_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-31 of the vulnerable file.

package com.browserup.bup.rest.validation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { LongPositiveConstraint.LongPositiveValidator.class })
public @interface LongPositiveConstraint {

  String message() default "";

  String paramName() default "";

  Class<?>[] groups() default {};

  int value();

  Class<? extends Payload>[] payload() default {};

  class LongPositiveValidator implements ConstraintValidator<LongPositiveConstraint, String> {
    private static final Logger LOG = LoggerFactory.getLogger(LongPositiveValidator.class);

    @Override
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 import javax.validation.ConstraintValidatorContext;
 import javax.validation.Payload;
 
+import com.browserup.bup.rest.validation.util.MessageSanitizer;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
@@ -41,12 +42,14 @@
         longValue = Long.parseLong(value);
       } catch (NumberFormatException ex) {
         failed = true;
-        errorMessage = String.format("Invalid integer value: '%s'", value);
+        String escapedValue = MessageSanitizer.escape(value);
+        errorMessage = String.format("Invalid integer value: '%s'", escapedValue);
       }
 
       if (!failed && longValue < 0) {
         failed = true;
-        errorMessage = String.format("Expected positive integer value, got: '%s'", value);
+        String escapedValue = MessageSanitizer.escape(value);
+        errorMessage = String.format("Expected positive integer value, got: '%s'", escapedValue);
       }
 
       if (!failed) {
```
