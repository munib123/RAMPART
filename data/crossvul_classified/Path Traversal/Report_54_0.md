# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 54_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `54_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

/*
 * Copyright (C) 2012 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retrofit2;

import java.io.IOException;
import javax.annotation.Nullable;
import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.Request;
import okhttp3.RequestBody;
import okio.Buffer;
import okio.BufferedSink;

final class RequestBuilder {
  private static final char[] HEX_DIGITS =
      { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  private static final String PATH_SEGMENT_ALWAYS_ENCODE_SET = " \"<>^`{}|\\?#";

  private final String method;

  private final HttpUrl baseUrl;
  private @Nullable String relativeUrl;
  private @Nullable HttpUrl.Builder urlBuilder;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 package retrofit2;
 
 import java.io.IOException;
+import java.util.regex.Pattern;
 import javax.annotation.Nullable;
 import okhttp3.FormBody;
 import okhttp3.Headers;
@@ -32,6 +33,21 @@
       { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
   private static final String PATH_SEGMENT_ALWAYS_ENCODE_SET = " \"<>^`{}|\\?#";
 
+  /**
+   * Matches strings that contain {@code .} or {@code ..} as a complete path segment. This also
+   * matches dots in their percent-encoded form, {@code %2E}.
+   *
+   * <p>It is okay to have these strings within a larger path segment (like {@code a..z} or {@code
+   * index.html}) but when alone they have a special meaning. A single dot resolves to no path
+   * segment so {@code /one/./three/} becomes {@code /one/three/}. A double-dot pops the preceding
+   * directory, so {@code /one/../three/} becomes {@code /three/}.
+   *
+   * <p>We forbid these in Retrofit paths because they're likely to have the unintended effect.
+   * For example, passing {@code ..} to {@code DELETE /account/book/{isbn}/} yields {@code DELETE
+   * /account/}.
+   */
+  private static final Pattern PATH_TRAVERSAL = Pattern.compile("(.*/)?(\\.|%2e|%2E){1,2}(/.*)?");
+
   private final String method;
 
   private final HttpUrl baseUrl;
@@ -91,7 +107,13 @@
       // The relative URL is cleared when the first query parameter is set.
       throw new AssertionError();
     }
-    relativeUrl = relativeUrl.replace("{" + name + "}", canonicalizeForPath(value, encoded));
+    String replacement = canonicalizeForPath(value, encoded);
+    String newRelativeUrl = relativeUrl.replace("{" + name + "}", replacement);
+    if (PATH_TRAVERSAL.matcher(newRelativeUrl).matches()) {
+      throw new IllegalArgumentException(
+          "@Path parameters shouldn't perform path traversal ('.' or '..'): " + value);
+    }
+    relativeUrl = newRelativeUrl;
   }
 
   private static String canonicalizeForPath(String input, boolean alreadyEncoded) {
```
