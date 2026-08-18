# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 133-173 of the vulnerable file.

    }

    @Test
    public void doubleInit() {
        BackendManager b1 = new BackendManager(config,log);
        BackendManager b2 = new BackendManager(config,log);
        b2.destroy();
        b1.destroy();
    }

    @Test
    public void remoteAccessCheck() {
        BackendManager backendManager = new BackendManager(config,log);
        assertTrue(backendManager.isRemoteAccessAllowed("localhost","127.0.0.1"));
        backendManager.destroy();
    }

    @Test
    public void corsAccessCheck() {
        BackendManager backendManager = new BackendManager(config,log);
        assertTrue(backendManager.isCorsAccessAllowed("http://bla.com"));
        backendManager.destroy();
    }

    @Test
    public void convertError() throws MalformedObjectNameException {
        BackendManager backendManager = new BackendManager(config,log);
        Exception exp = new IllegalArgumentException("Hans",new IllegalStateException("Kalb"));
        JmxRequest req = new JmxRequestBuilder(RequestType.READ,"java.lang:type=Memory").build();
        JSONObject jsonError = (JSONObject) backendManager.convertExceptionToJson(exp,req);
        assertTrue(!jsonError.containsKey("stackTrace"));
        assertEquals(jsonError.get("message"),"Hans");
        assertEquals(((JSONObject) jsonError.get("cause")).get("message"),"Kalb");
        backendManager.destroy();
    }

    // =========================================================================================

    static class RequestDispatcherTest implements RequestDispatcher {

        static boolean called = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,7 @@
     @Test
     public void corsAccessCheck() {
         BackendManager backendManager = new BackendManager(config,log);
-        assertTrue(backendManager.isCorsAccessAllowed("http://bla.com"));
+        assertTrue(backendManager.isOriginAllowed("http://bla.com",false));
         backendManager.destroy();
     }
 
```
