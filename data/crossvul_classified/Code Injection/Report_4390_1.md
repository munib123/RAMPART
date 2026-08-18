# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4390_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4390_1`)

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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { NotBlankConstraint.NotBlankValidator.class })
public @interface NotBlankConstraint {

  String message() default "";

  String paramName() default "";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  class NotBlankValidator implements ConstraintValidator<NotBlankConstraint, Object> {
    private static final Logger LOG = LoggerFactory.getLogger(NotBlankValidator.class);

    @Override
    public void initialize(NotBlankConstraint constraintAnnotation) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 import javax.validation.ConstraintValidatorContext;
 import javax.validation.Payload;
 
+import com.browserup.bup.rest.validation.util.MessageSanitizer;
 import org.apache.commons.lang3.StringUtils;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
@@ -36,7 +37,9 @@
       if (value != null && StringUtils.isNotEmpty(String.valueOf(value))) {
         return true;
       }
-      String errorMessage = String.format("Expected not empty value, got '%s'", value);
+
+      String escapedValue = MessageSanitizer.escape(value == null ? null : value.toString());
+      String errorMessage = String.format("Expected not empty value, got '%s'", escapedValue);
       LOG.warn(errorMessage);
 
       context.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();
```
