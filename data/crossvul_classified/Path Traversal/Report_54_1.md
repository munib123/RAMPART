# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 54_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `54_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 859-899 of the vulnerable file.

    }
    Request request = buildRequest(Example.class, "baz/\r\nheader: blue");
    assertThat(request.method()).isEqualTo("GET");
    assertThat(request.headers().size()).isZero();
    assertThat(request.url().toString()).isEqualTo("http://example.com/foo/bar/baz%2F%0D%0Aheader:%20blue/");
    assertThat(request.body()).isNull();
  }

  @Test public void getWithEncodedPathStillPreventsRequestSplitting() {
    class Example {
      @GET("/foo/bar/{ping}/") //
      Call<ResponseBody> method(@Path(value = "ping", encoded = true) String ping) {
        return null;
      }
    }
    Request request = buildRequest(Example.class, "baz/\r\npong");
    assertThat(request.method()).isEqualTo("GET");
    assertThat(request.headers().size()).isZero();
    assertThat(request.url().toString()).isEqualTo("http://example.com/foo/bar/baz/pong/");
    assertThat(request.body()).isNull();
  }

  @Test public void pathParamRequired() {
    class Example {
      @GET("/foo/bar/{ping}/") //
      Call<ResponseBody> method(@Path("ping") String ping) {
        return null;
      }
    }
    try {
      buildRequest(Example.class, new Object[] { null });
      fail();
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage()).isEqualTo("Path parameter \"ping\" value must not be null.");
    }
  }

  @Test public void getWithQueryParam() {
    class Example {
      @GET("/foo/bar/") //
      Call<ResponseBody> method(@Query("ping") String ping) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -878,6 +878,88 @@
     assertThat(request.body()).isNull();
   }
 
+  @Test public void pathParametersAndPathTraversal() {
+    class Example {
+      @GET("/foo/bar/{ping}/") //
+      Call<ResponseBody> method(@Path(value = "ping") String ping) {
+        return null;
+      }
+    }
+
+    assertMalformedRequest(Example.class, ".");
+    assertMalformedRequest(Example.class, "..");
+
+    assertThat(buildRequest(Example.class, "./a").url().encodedPath())
+        .isEqualTo("/foo/bar/.%2Fa/");
+    assertThat(buildRequest(Example.class, "a/.").url().encodedPath())
+        .isEqualTo("/foo/bar/a%2F./");
+    assertThat(buildRequest(Example.class, "a/..").url().encodedPath())
+        .isEqualTo("/foo/bar/a%2F../");
+    assertThat(buildRequest(Example.class, "../a").url().encodedPath())
+        .isEqualTo("/foo/bar/..%2Fa/");
+    assertThat(buildRequest(Example.class, "..\\..").url().encodedPath())
+        .isEqualTo("/foo/bar/..%5C../");
+
+    assertThat(buildRequest(Example.class, "%2E").url().encodedPath())
+        .isEqualTo("/foo/bar/%252E/");
+    assertThat(buildRequest(Example.class, "%2E%2E").url().encodedPath())
+        .isEqualTo("/foo/bar/%252E%252E/");
+  }
+
+  @Test public void encodedPathParametersAndPathTraversal() {
+    class Example {
+      @GET("/foo/bar/{ping}/") //
+      Call<ResponseBody> method(@Path(value = "ping", encoded = true) String ping) {
+        return null;
+      }
+    }
+
+    assertMalformedRequest(Example.class, ".");
+    assertMalformedRequest(Example.class, "%2E");
+    assertMalformedRequest(Example.class, "%2e");
+    assertMalformedRequest(Example.class, "..");
+    assertMalformedRequest(Example.class, "%2E.");
+    assertMalformedRequest(Example.class, "%2e.");
+    assertMalformedRequest(Example.class, ".%2E");
+    assertMalformedRequest(Example.class, ".%2e");
+    assertMalformedRequest(Example.class, "%2E%2e");
+    assertMalformedRequest(Example.class, "%2e%2E");
+    assertMalformedRequest(Example.class, "./a");
+    assertMalformedRequest(Example.class, "a/.");
+    assertMalformedRequest(Example.class, "../a");
+    assertMalformedRequest(Example.class, "a/..");
+    assertMalformedRequest(Example.class, "a/../b");
+    assertMalformedRequest(Example.class, "a/%2e%2E/b");
+
+    assertThat(buildRequest(Example.class, "...").url().encodedPath())
+        .isEqualTo("/foo/bar/.../");
+    assertThat(buildRequest(Example.class, "a..b").url().encodedPath())
+        .isEqualTo("/foo/bar/a..b/");
+    assertThat(buildRequest(Example.class, "a..").url().encodedPath())
+        .isEqualTo("/foo/bar/a../");
+    assertThat(buildRequest(Example.class, "a..b").url().encodedPath())
+        .isEqualTo("/foo/bar/a..b/");
+    assertThat(buildRequest(Example.class, "..b").url().encodedPath())
+        .isEqualTo("/foo/bar/..b/");
+    assertThat(buildRequest(Example.class, "..\\..").url().encodedPath())
+        .isEqualTo("/foo/bar/..%5C../");
+  }
+
+  @Test public void dotDotsOkayWhenNotFullPathSegment() {
+    class Example {
+      @GET("/foo{ping}bar/") //
+      Call<ResponseBody> method(@Path(value = "ping", encoded = true) String ping) {
+        return null;
+      }
+    }
+
+    assertMalformedRequest(Example.class, "/./");
+    assertMalformedRequest(Example.class, "/../");
+
+    assertThat(buildRequest(Example.class, ".").url().encodedPath()).isEqualTo("/foo.bar/");
+    assertThat(buildRequest(Example.class, "..").url().encodedPath()).isEqualTo("/foo..bar/");
+  }
+
   @Test public void pathParamRequired() {
     class Example {
       @GET("/foo/bar/{ping}/") //
@@ -2783,4 +2865,12 @@
 
     return buildRequest(cls, retrofitBuilder, args);
   }
+
+  static void assertMalformedRequest(Class<?> cls, Object... args) {
+    try {
+      Request request = buildRequest(cls, args);
+      fail("expected a malformed request but was " + request);
+    } catch (IllegalArgumentException expected) {
+    }
+  }
 }
```
