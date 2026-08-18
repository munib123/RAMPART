# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4548_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4548_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package io.dropwizard.validation.selfvalidating;

import javax.validation.ConstraintValidatorContext;

/**
 * This class is a simple wrapper around the ConstraintValidatorContext of hibernate validation.
 * It collects all the violations of the SelfValidation methods of an object.
 */
public class ViolationCollector {

    private boolean violationOccurred = false;
    private ConstraintValidatorContext context;


    public ViolationCollector(ConstraintValidatorContext context) {
        this.context = context;
    }

    /**
     * Adds a new violation to this collector. This also sets violationOccurred to true.
     *
     * @param msg the message of the violation
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,12 +1,16 @@
 package io.dropwizard.validation.selfvalidating;
 
+import javax.annotation.Nullable;
 import javax.validation.ConstraintValidatorContext;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 /**
  * This class is a simple wrapper around the ConstraintValidatorContext of hibernate validation.
  * It collects all the violations of the SelfValidation methods of an object.
  */
 public class ViolationCollector {
+    private static final Pattern ESCAPE_PATTERN = Pattern.compile("\\$\\{");
 
     private boolean violationOccurred = false;
     private ConstraintValidatorContext context;
@@ -17,14 +21,80 @@
     }
 
     /**
-     * Adds a new violation to this collector. This also sets violationOccurred to true.
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
      *
-     * @param msg the message of the violation
+     * @param message the message of the violation (any EL expression will be escaped and not parsed)
      */
-    public void addViolation(String msg) {
+    public void addViolation(String message) {
         violationOccurred = true;
-        context.buildConstraintViolationWithTemplate(msg)
-            .addConstraintViolation();
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 2.0.2
+     */
+    public void addViolation(String propertyName, String message) {
+        violationOccurred = true;
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addPropertyNode(propertyName)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property with the violation
+     * @param index        the index of the element with the violation
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 2.0.2
+     */
+    public void addViolation(String propertyName, Integer index, String message) {
+        violationOccurred = true;
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addPropertyNode(propertyName)
+                .addBeanNode().inIterable().atIndex(index)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property with the violation
+     * @param key          the key of the element with the violation
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 2.0.2
+     */
+    public void addViolation(String propertyName, String key, String message) {
+        violationOccurred = true;
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addPropertyNode(propertyName)
+                .addBeanNode().inIterable().atKey(key)
+                .addConstraintViolation();
+    }
+
+    @Nullable
+    private String escapeEl(@Nullable String s) {
+        if (s == null || s.isEmpty()) {
+            return s;
+        }
+
+        final Matcher m = ESCAPE_PATTERN.matcher(s);
+        final StringBuffer sb = new StringBuffer(s.length() + 16);
+        while (m.find()) {
+            m.appendReplacement(sb, "\\\\\\${");
+        }
+        m.appendTail(sb);
+
+        return sb.toString();
     }
 
     /**
```
