# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 3891_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3891_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

package io.dropwizard.validation.selfvalidating;

import javax.annotation.Nullable;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is a simple wrapper around the ConstraintValidatorContext of hibernate validation.
 * It collects all the violations of the SelfValidation methods of an object.
 */
public class ViolationCollector {
    private static final Pattern ESCAPE_PATTERN = Pattern.compile("\\$\\{");

    private boolean violationOccurred = false;
    private ConstraintValidatorContext context;


    public ViolationCollector(ConstraintValidatorContext context) {
        this.context = context;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,64 +1,116 @@
 package io.dropwizard.validation.selfvalidating;
+
+import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;
 
 import javax.annotation.Nullable;
 import javax.validation.ConstraintValidatorContext;
-import java.util.regex.Matcher;
-import java.util.regex.Pattern;
+import java.util.Collections;
+import java.util.Map;
+
+import static io.dropwizard.validation.InterpolationHelper.escapeMessageParameter;
 
 /**
  * This class is a simple wrapper around the ConstraintValidatorContext of hibernate validation.
  * It collects all the violations of the SelfValidation methods of an object.
  */
 public class ViolationCollector {
-    private static final Pattern ESCAPE_PATTERN = Pattern.compile("\\$\\{");
+    private final ConstraintValidatorContext constraintValidatorContext;
+    private final boolean escapeExpressions;
 
     private boolean violationOccurred = false;
-    private ConstraintValidatorContext context;
 
+    public ViolationCollector(ConstraintValidatorContext constraintValidatorContext) {
+        this(constraintValidatorContext, true);
+    }
 
-    public ViolationCollector(ConstraintValidatorContext context) {
-        this.context = context;
+    public ViolationCollector(ConstraintValidatorContext constraintValidatorContext, boolean escapeExpressions) {
+        this.constraintValidatorContext = constraintValidatorContext;
+        this.escapeExpressions = escapeExpressions;
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     * <p>
+     * Prefer the method with explicit message parameters if you want to interpolate the message.
+     *
+     * @param message the message of the violation
+     * @see #addViolation(String, Map)
+     */
+    public void addViolation(String message) {
+        addViolation(message, Collections.emptyMap());
     }
 
     /**
      * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
      *
-     * @param message the message of the violation (any EL expression will be escaped and not parsed)
+     * @param message           the message of the violation
+     * @param messageParameters a map of message parameters which can be interpolated in the violation message
+     * @since 2.0.3
      */
-    public void addViolation(String message) {
+    public void addViolation(String message, Map<String, Object> messageParameters) {
         violationOccurred = true;
-        String messageTemplate = escapeEl(message);
-        context.buildConstraintViolationWithTemplate(messageTemplate)
+        getContextWithMessageParameters(messageParameters)
+                .buildConstraintViolationWithTemplate(sanitizeTemplate(message))
                 .addConstraintViolation();
     }
 
     /**
      * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     * <p>
+     * Prefer the method with explicit message parameters if you want to interpolate the message.
      *
      * @param propertyName the name of the property
-     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @param message      the message of the violation
+     * @see #addViolation(String, String, Map)
      * @since 2.0.2
      */
     public void addViolation(String propertyName, String message) {
+        addViolation(propertyName, message, Collections.emptyMap());
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName      the name of the property
+     * @param message           the message of the violation
+     * @param messageParameters a map of message parameters which can be interpolated in the violation message
+     * @since 2.0.3
+     */
+    public void addViolation(String propertyName, String message, Map<String, Object> messageParameters) {
         violationOccurred = true;
-        String messageTemplate = escapeEl(message);
-        context.buildConstraintViolationWithTemplate(messageTemplate)
+        getContextWithMessageParameters(messageParameters)
+                .buildConstraintViolationWithTemplate(sanitizeTemplate(message))
                 .addPropertyNode(propertyName)
                 .addConstraintViolation();
     }
 
     /**
      * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     * Prefer the method with explicit message parameters if you want to interpolate the message.
      *
      * @param propertyName the name of the property with the violation
      * @param index        the index of the element with the violation
      * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @see ViolationCollector#addViolation(String, Integer, String, Map)
      * @since 2.0.2
      */
     public void addViolation(String propertyName, Integer index, String message) {
+        addViolation(propertyName, index, message, Collections.emptyMap());
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName      the name of the property with the violation
+     * @param index             the index of the element with the violation
+     * @param message           the message of the violation
+     * @param messageParameters a map of message parameters which can be interpolated in the violation message
+     * @since 2.0.3
+     */
+    public void addViolation(String propertyName, Integer index, String message, Map<String, Object> messageParameters) {
         violationOccurred = true;
-        String messageTemplate = escapeEl(message);
-        context.buildConstraintViolationWithTemplate(messageTemplate)
+        getContextWithMessageParameters(messageParameters)
+                .buildConstraintViolationWithTemplate(sanitizeTemplate(message))
                 .addPropertyNode(propertyName)
                 .addBeanNode().inIterable().atIndex(index)
                 .addConstraintViolation();
@@ -69,32 +121,46 @@
      *
      * @param propertyName the name of the property with the violation
      * @param key          the key of the element with the violation
-     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @param message      the message of the violation
      * @since 2.0.2
      */
     public void addViolation(String propertyName, String key, String message) {
+        addViolation(propertyName, key, message, Collections.emptyMap());
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName      the name of the property with the violation
+     * @param key               the key of the element with the violation
+     * @param message           the message of the violation
+     * @param messageParameters a map of message parameters which can be interpolated in the violation message
+     * @since 2.0.3
+     */
+    public void addViolation(String propertyName, String key, String message, Map<String, Object> messageParameters) {
         violationOccurred = true;
-        String messageTemplate = escapeEl(message);
+        final String messageTemplate = sanitizeTemplate(message);
+        final HibernateConstraintValidatorContext context = getContextWithMessageParameters(messageParameters);
         context.buildConstraintViolationWithTemplate(messageTemplate)
                 .addPropertyNode(propertyName)
                 .addBeanNode().inIterable().atKey(key)
                 .addConstraintViolation();
     }
 
+    private HibernateConstraintValidatorContext getContextWithMessageParameters(Map<String, Object> messageParameters) {
... (diff truncated)
```
