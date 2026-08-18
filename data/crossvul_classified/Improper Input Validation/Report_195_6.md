# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 32-77 of the vulnerable file.

import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.http.impl.HeadersAdaptor;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.SocketAddress;
import io.vertx.test.netty.TestLoggerFactory;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.IntStream;

import static io.vertx.test.core.TestUtils.*;
import static java.util.Collections.*;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public abstract class HttpTest extends HttpTestBase {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,12 +49,7 @@
 import java.io.UnsupportedEncodingException;
 import java.net.InetAddress;
 import java.net.URLEncoder;
-import java.util.ArrayList;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.List;
-import java.util.Map;
-import java.util.UUID;
+import java.util.*;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutorService;
@@ -64,6 +59,7 @@
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.concurrent.atomic.AtomicInteger;
 import java.util.concurrent.atomic.AtomicReference;
+import java.util.function.BiConsumer;
 import java.util.function.Consumer;
 import java.util.function.Function;
 import java.util.stream.IntStream;
@@ -86,7 +82,7 @@
     super.setUp();
     testDir = testFolder.newFolder();
   }
-    
+
   protected HttpServerOptions createBaseServerOptions() {
     return new HttpServerOptions().setPort(DEFAULT_HTTP_PORT).setHost(DEFAULT_HTTP_HOST);
   }
@@ -176,7 +172,7 @@
     }
   }
 
-    
+
   @Test
   public void testLowerCaseHeaders() {
     server.requestHandler(req -> {
@@ -4272,6 +4268,78 @@
     return headers;
   }
 
+  @Test
+  public void testHttpClientRequestHeadersDontContainCROrLF() throws Exception {
+    server.requestHandler(req -> {
+      req.headers().forEach(header -> {
+        String name = header.getKey();
+        switch (name.toLowerCase()) {
+          case "host":
+          case ":method":
+          case ":path":
+          case ":scheme":
+          case ":authority":
+            break;
+          default:
+            fail("Unexpected header " + name);
+        }
+      });
+      testComplete();
+    });
+    startServer();
+    HttpClientRequest req = client.get(DEFAULT_HTTP_PORT, DEFAULT_HTTP_HOST, DEFAULT_TEST_URI, resp -> {});
+    List<BiConsumer<String, String>> list = Arrays.asList(
+      req::putHeader,
+      req.headers()::set,
+      req.headers()::add
+    );
+    list.forEach(cs -> {
+      try {
+        req.putHeader("header-name: header-value\r\nanother-header", "another-value");
+        fail();
+      } catch (IllegalArgumentException e) {
+      }
+    });
+    assertEquals(0, req.headers().size());
+    req.end();
+    await();
+  }
+
+  @Test
+  public void testHttpServerResponseHeadersDontContainCROrLF() throws Exception {
+    server.requestHandler(req -> {
+      List<BiConsumer<String, String>> list = Arrays.asList(
+        req.response()::putHeader,
+        req.response().headers()::set,
+        req.response().headers()::add
+      );
+      list.forEach(cs -> {
+        try {
+          cs.accept("header-name: header-value\r\nanother-header", "another-value");
+          fail();
+        } catch (IllegalArgumentException e) {
+        }
+      });
+      assertEquals(Collections.emptySet(), req.response().headers().names());
+      req.response().end();
+    });
+    startServer();
+    client.getNow(DEFAULT_HTTP_PORT, DEFAULT_HTTP_HOST, DEFAULT_TEST_URI, resp -> {
+      resp.headers().forEach(header -> {
+        String name = header.getKey();
+        switch (name.toLowerCase()) {
+          case ":status":
+          case "content-length":
+            break;
+          default:
+            fail("Unexpected header " + name);
+        }
+      });
+      testComplete();
+    });
+    await();
+  }
+
   /*
   @Test
   public void testReset() throws Exception {
```
