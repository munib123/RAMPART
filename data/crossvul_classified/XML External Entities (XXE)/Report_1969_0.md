# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1969_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1969_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 45-85 of the vulnerable file.

      if (seedString != null) {
        seed = Long.parseLong(seedString, 16);
      } else {
        // Use java.util.Random's default constructor to generate a seed since
        // it does a pretty good job of making a good non-crypto-strong seed.
        seed = new Random().nextLong();
      }
    }

    // Dump the seed so that failures can be reproduced with only this line
    // from the test log.
    System.err.println("Fuzzing with -Dfuzz.seed=" + Long.toHexString(seed));
    System.err.flush();

    Random rnd = new Random(seed);
    for (String fuzzyWuzzyString : new FuzzyStringGenerator(rnd)) {
      try {
        String sanitized0 = JsonSanitizer.sanitize(fuzzyWuzzyString);
        String sanitized1 = JsonSanitizer.sanitize(sanitized0);
        // Test idempotence.
        assertEquals(fuzzyWuzzyString + "  =>  " + sanitized0, sanitized0,
                     sanitized1);
      } catch (Throwable th) {
        System.err.println("Failed on `" + fuzzyWuzzyString + "`");
        hexDump(fuzzyWuzzyString.getBytes("UTF16"), System.err);
        System.err.println("");
        throw th;
      }
      if (--nRuns <= 0) { break; }
    }
  }


  private static void hexDump(byte[] bytes, Appendable app)
    throws IOException {
    for (int i = 0; i < bytes.length; ++i) {
      if ((i % 16) == 0) {
        if (i != 0) {
          app.append('\n');
        }
      } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,32 @@
         String sanitized0 = JsonSanitizer.sanitize(fuzzyWuzzyString);
         String sanitized1 = JsonSanitizer.sanitize(sanitized0);
         // Test idempotence.
+        if (!sanitized0.equals(sanitized1)) {
+          int commonPrefixLen = 0;
+          int minLength = Math.min(sanitized0.length(), sanitized1.length());
+          while (commonPrefixLen < minLength) {
+            if (sanitized0.charAt(commonPrefixLen) != sanitized1.charAt(commonPrefixLen)) {
+              break;
+            }
+            ++commonPrefixLen;
+          }
+
+          int right0 = sanitized0.length();
+          int right1 = sanitized1.length();
+          while (right0 > commonPrefixLen && right1 > commonPrefixLen) {
+            if (sanitized0.charAt(right0 - 1) != sanitized1.charAt(right1 - 1)) {
+              break;
+            }
+            --right0;
+            --right1;
+          }
+
+          int commonSuffixLen = sanitized0.length() - right0;
+
+          System.err.println("Difference at " + commonPrefixLen + " to -" + commonSuffixLen);
+          System.err.println("Before: " + excerpt(sanitized0, commonPrefixLen, right0));
+          System.err.println("After:  " + excerpt(sanitized0, commonPrefixLen, right1));
+        }
         assertEquals(fuzzyWuzzyString + "  =>  " + sanitized0, sanitized0,
                      sanitized1);
       } catch (Throwable th) {
@@ -89,6 +115,23 @@
       app.append("0123456789ABCDEF".charAt((b >>> 4) & 0xf));
       app.append("0123456789ABCDEF".charAt((b >>> 0) & 0xf));
     }
+  }
+
+  private static String excerpt(String s, int left, int right) {
+    int leftIncl = left - 10;
+    boolean ellipseLeft = leftIncl > 0;
+    if (!ellipseLeft) { leftIncl = 0; }
+
+    int rightIncl = right + 10;
+    boolean ellipseRight = s.length() > rightIncl;
+    if (!ellipseRight) {
+      rightIncl = s.length();
+    }
+
+    return s.substring(leftIncl, rightIncl)
+            .replace("\r", "\\r")
+            .replace("\n", "\\n")
+            .replace("\\", "\\\\");
   }
 }
 
```
