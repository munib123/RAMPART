# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4390_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4390_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-32 of the vulnerable file.

package com.browserup.bup.rest.validation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.regex.Pattern;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { PatternConstraint.PatternValidator.class })
public @interface PatternConstraint {

  String message() default "";

  String paramName() default "";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  class PatternValidator implements ConstraintValidator<PatternConstraint, String> {
    private static final Logger LOG = LoggerFactory.getLogger(PatternValidator.class);

    @Override
    public void initialize(PatternConstraint constraintAnnotation) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 import javax.validation.ConstraintValidatorContext;
 import javax.validation.Payload;
 
+import com.browserup.bup.rest.validation.util.MessageSanitizer;
 import org.apache.commons.lang3.StringUtils;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
@@ -42,7 +43,8 @@
         Pattern.compile(value);
         return true;
       } catch (Exception ex) {
-        String errorMessage = String.format("URL parameter '%s' is not a valid regexp", value);
+        String escapedValue = MessageSanitizer.escape(value);
+        String errorMessage = String.format("URL parameter '%s' is not a valid regexp", escapedValue);
         LOG.warn(errorMessage);
 
         context.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();
```
