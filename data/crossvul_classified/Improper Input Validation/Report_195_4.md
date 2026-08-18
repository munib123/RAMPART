# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 504-524 of the vulnerable file.

        if (pos < to) {
          int ret = 0;
          while (pos < to) {
            int ch = value.charAt(pos++);
            if (ch >= '0' && ch < '9') {
              ret = ret * 10 + (ch - '0');
            } else {
              ret = -1;
              break;
            }
          }
          if (ret > -1) {
            return ret;
          }
        }
      }
      pos = next;
    }
    return -1;
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -521,4 +521,23 @@
     }
     return -1;
   }
+
+  public static void validateHeader(CharSequence name, CharSequence value) {
+    validateHeader(name);
+    validateHeader(value);
+  }
+
+  public static void validateHeader(CharSequence name, Iterable<? extends CharSequence> values) {
+    validateHeader(name);
+    values.forEach(HttpUtils::validateHeader);
+  }
+
+  public static void validateHeader(CharSequence value) {
+    for (int i = 0;i < value.length();i++) {
+      char c = value.charAt(i);
+      if (c == '\r' || c == '\n') {
+        throw new IllegalArgumentException("Illegal header character: " + ((int)c));
+      }
+    }
+  }
 }
```
