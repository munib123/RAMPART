# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_9
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_9`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 48-88 of the vulnerable file.

    private HttpRequestHandler handler;

    @BeforeMethod
    public void setup() {
        backend = createMock(BackendManager.class);
        expect(backend.isDebug()).andReturn(true).anyTimes();

        handler = new HttpRequestHandler(new Configuration(),backend, createDummyLogHandler());
    }

    @AfterMethod
    public void tearDown() {
        verify(backend);
    }

    @Test
    public void accessAllowed() {
        expect(backend.isRemoteAccessAllowed("localhost","127.0.0.1")).andReturn(true);
        replay(backend);

        handler.checkClientIPAccess("localhost","127.0.0.1");
    }

    @Test(expectedExceptions = { SecurityException.class })
    public void accessDenied() {
        expect(backend.isRemoteAccessAllowed("localhost","127.0.0.1")).andReturn(false);
        replay(backend);

        handler.checkClientIPAccess("localhost","127.0.0.1");
    }

    @Test
    public void get() throws InstanceNotFoundException, IOException, ReflectionException, AttributeNotFoundException, MBeanException {
        JSONObject resp = new JSONObject();
        expect(backend.handleRequest(isA(JmxReadRequest.class))).andReturn(resp);
        replay(backend);

        JSONObject response = (JSONObject) handler.handleGetRequest("/jolokia", HttpTestUtil.HEAP_MEMORY_GET_REQUEST, null);
        assertTrue(response == resp);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
         expect(backend.isRemoteAccessAllowed("localhost","127.0.0.1")).andReturn(true);
         replay(backend);
 
-        handler.checkClientIPAccess("localhost","127.0.0.1");
+        handler.checkAccess("localhost", "127.0.0.1",null);
     }
 
     @Test(expectedExceptions = { SecurityException.class })
@@ -73,8 +73,18 @@
         expect(backend.isRemoteAccessAllowed("localhost","127.0.0.1")).andReturn(false);
         replay(backend);
 
-        handler.checkClientIPAccess("localhost","127.0.0.1");
-    }
+        handler.checkAccess("localhost", "127.0.0.1",null);
+    }
+
+    @Test(expectedExceptions = { SecurityException.class })
+    public void accessDeniedViaOrigin() {
+        expect(backend.isRemoteAccessAllowed("localhost","127.0.0.1")).andReturn(true);
+        expect(backend.isOriginAllowed("www.jolokia.org",true)).andReturn(false);
+        replay(backend);
+
+        handler.checkAccess("localhost", "127.0.0.1","www.jolokia.org");
+    }
+
 
     @Test
     public void get() throws InstanceNotFoundException, IOException, ReflectionException, AttributeNotFoundException, MBeanException {
@@ -152,7 +162,7 @@
     public void preflightCheck() {
         String origin = "http://bla.com";
         String headers ="X-Data: Test";
-        expect(backend.isCorsAccessAllowed(origin)).andReturn(true);
+        expect(backend.isOriginAllowed(origin,false)).andReturn(true);
         replay(backend);
 
         Map<String,String> ret =  handler.handleCorsPreflightRequest(origin, headers);
@@ -163,7 +173,7 @@
     public void preflightCheckNegative() {
         String origin = "http://bla.com";
         String headers ="X-Data: Test";
-        expect(backend.isCorsAccessAllowed(origin)).andReturn(false);
+        expect(backend.isOriginAllowed(origin,false)).andReturn(false);
         replay(backend);
 
         Map<String,String> ret =  handler.handleCorsPreflightRequest(origin, headers);
```
