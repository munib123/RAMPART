# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 3891_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3891_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package io.dropwizard.validation.selfvalidating;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The annotated element has methods annotated by
 * {@link io.dropwizard.validation.selfvalidating.SelfValidation}.
 * Those methods are executed on validation.
 */
@Documented
@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = SelfValidatingValidator.class)
public @interface SelfValidating {

    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
+import java.util.Map;
 
 /**
  * The annotated element has methods annotated by
@@ -24,4 +25,16 @@
     Class<?>[] groups() default {};
 
     Class<? extends Payload>[] payload() default {};
+
+    /**
+     * Escape EL expressions to avoid template injection attacks.
+     * <p>
+     * This has serious security implications and you will
+     * have to escape the violation messages added to {@link ViolationCollector} appropriately.
+     *
+     * @see ViolationCollector#addViolation(String, Map)
+     * @see ViolationCollector#addViolation(String, String, Map)
+     * @see ViolationCollector#addViolation(String, Integer, String, Map)
+     */
+    boolean escapeExpressions() default true;
 }
```
