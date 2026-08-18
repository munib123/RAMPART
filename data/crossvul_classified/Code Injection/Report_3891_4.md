# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 3891_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3891_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 1-23 of the vulnerable file.

package io.dropwizard.validation;

import io.dropwizard.validation.selfvalidating.SelfValidating;
import io.dropwizard.validation.selfvalidating.SelfValidation;
import io.dropwizard.validation.selfvalidating.ViolationCollector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.annotation.concurrent.NotThreadSafe;
import javax.validation.Validator;

import static org.assertj.core.api.Assertions.assertThat;

@NotThreadSafe
public class SelfValidationTest {

    private static final String FAILED = "failed";
    private static final String FAILED_RESULT = " " + FAILED;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 package io.dropwizard.validation;
 
+import io.dropwizard.util.Maps;
 import io.dropwizard.validation.selfvalidating.SelfValidating;
 import io.dropwizard.validation.selfvalidating.SelfValidation;
 import io.dropwizard.validation.selfvalidating.ViolationCollector;
@@ -12,6 +13,7 @@
 
 import javax.annotation.concurrent.NotThreadSafe;
 import javax.validation.Validator;
+import java.util.Collections;
 
 import static org.assertj.core.api.Assertions.assertThat;
 
@@ -146,9 +148,45 @@
         @SelfValidation
         public void validateFail(ViolationCollector col) {
             col.addViolation("${'value'}");
+            col.addViolation("$\\A{1+1}");
+            col.addViolation("{value}", Collections.singletonMap("value", "TEST"));
             col.addViolation("${'property'}", "${'value'}");
             col.addViolation("${'property'}", 1, "${'value'}");
             col.addViolation("${'property'}", "${'key'}", "${'value'}");
+        }
+    }
+
+    @SelfValidating(escapeExpressions = false)
+    public static class EscapingDisabledExample {
+        @SuppressWarnings("unused")
+        @SelfValidation
+        public void validateFail(ViolationCollector col) {
+            col.addViolation("${'value'}");
+            col.addViolation("$\\A{1+1}");
+            col.addViolation("{value}", Collections.singletonMap("value", "TEST"));
+            col.addViolation("${'property'}", "${'value'}");
+            col.addViolation("${'property'}", 1, "${'value'}");
+            col.addViolation("${'property'}", "${'key'}", "${'value'}");
+        }
+    }
+
+    @SelfValidating(escapeExpressions = false)
+    public static class MessageParametersExample {
+        @SuppressWarnings("unused")
+        @SelfValidation
+        public void validateFail(ViolationCollector col) {
+            col.addViolation("{1+1}");
+            col.addViolation("{value}", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("No parameter", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("{value} {unsetParameter}", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("{value", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("value}", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("{  value  }", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("Mixed ${'value'} {value}", Collections.singletonMap("value", "VALUE"));
+            col.addViolation("Nested {value}", Collections.singletonMap("value", "${'nested'}"));
+            col.addViolation("{property}", "{value}", Maps.of("property", "PROPERTY", "value", "VALUE"));
+            col.addViolation("{property}", 1, "{value}", Maps.of("property", "PROPERTY", "value", "VALUE"));
+            col.addViolation("{property}", "{key}", "{value}", Maps.of("property", "PROPERTY", "key", "KEY", "value", "VALUE"));
         }
     }
 
@@ -271,13 +309,47 @@
     }
 
     @Test
-    public void violationMessagesAreEscaped() {
+    public void violationMessagesAreEscapedByDefault() {
         assertThat(ConstraintViolations.format(validator.validate(new InjectionExample()))).containsExactly(
+                " $\\A{1+1}",
                 " ${'value'}",
+                " {value}",
                 "${'property'} ${'value'}",
                 "${'property'}[${'key'}] ${'value'}",
                 "${'property'}[1] ${'value'}"
         );
         assertThat(TestLoggerFactory.getAllLoggingEvents()).isEmpty();
     }
+
+    @Test
+    public void violationMessagesAreInterpolatedIfEscapingDisabled() {
+        assertThat(ConstraintViolations.format(validator.validate(new EscapingDisabledExample()))).containsExactly(
+                " A2",
+                " TEST",
+                " value",
+                "${'property'} value",
+                "${'property'}[${'key'}] value",
+                "${'property'}[1] value"
+        );
+        assertThat(TestLoggerFactory.getAllLoggingEvents()).isEmpty();
+    }
+
+    @Test
+    public void messageParametersExample() {
+        assertThat(ConstraintViolations.format(validator.validate(new MessageParametersExample()))).containsExactly(
+                " Mixed value VALUE",
+                " Nested ${'nested'}",
+                " No parameter",
+                " VALUE",
+                " VALUE {unsetParameter}",
+                " value}",
+                " {  value  }",
+                " {1+1}",
+                " {value",
+                "{property} VALUE",
+                "{property}[1] VALUE",
+                "{property}[{key}] VALUE"
+        );
+        assertThat(TestLoggerFactory.getAllLoggingEvents()).isEmpty();
+    }
 }
```
