# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 108-149 of the vulnerable file.

        assertNull(cfg.get(ConfigKey.CALLBACK));
        assertNull(cfg.get(ConfigKey.DETECTOR_OPTIONS));

    }

    @Test
    public void initWithcustomAccessRestrictor() throws ServletException {
        prepareStandardInitialisation();
        servlet.destroy();
    }

    @Test
    public void initWithCustomLogHandler() throws Exception {
        servlet = new AgentServlet();
        config = createMock(ServletConfig.class);
        context = createMock(ServletContext.class);

        HttpTestUtil.prepareServletConfigMock(config, new String[]{ConfigKey.LOGHANDLER_CLASS.getKeyValue(), CustomLogHandler.class.getName()});
        HttpTestUtil.prepareServletContextMock(context,null);

        expect(config.getServletContext()).andReturn(context).anyTimes();
        expect(config.getServletName()).andReturn("jolokia").anyTimes();
        replay(config, context);

        servlet.init(config);
        servlet.destroy();

        assertTrue(CustomLogHandler.infoCount > 0);
    }

    @Test
    public void initWithAgentDiscoveryAndGivenUrl() throws ServletException, IOException, InterruptedException {
        checkMulticastAvailable();
        String url = "http://localhost:8080/jolokia";
        prepareStandardInitialisation(ConfigKey.DISCOVERY_AGENT_URL.getKeyValue(), url);
        // Wait listening thread to warm up
        Thread.sleep(1000);
        try {
            JolokiaDiscovery discovery = new JolokiaDiscovery("test",LogHandler.QUIET);
            List<JSONObject> in = discovery.lookupAgentsWithTimeout(500);
            for (JSONObject json : in) {
                if (json.get("url") != null && json.get("url").equals(url)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,8 +125,8 @@
         HttpTestUtil.prepareServletConfigMock(config, new String[]{ConfigKey.LOGHANDLER_CLASS.getKeyValue(), CustomLogHandler.class.getName()});
         HttpTestUtil.prepareServletContextMock(context,null);
 
-        expect(config.getServletContext()).andReturn(context).anyTimes();
-        expect(config.getServletName()).andReturn("jolokia").anyTimes();
+        expect(config.getServletContext()).andStubReturn(context);
+        expect(config.getServletName()).andStubReturn("jolokia");
         replay(config, context);
 
         servlet.init(config);
@@ -191,7 +191,7 @@
             StringWriter sw = initRequestResponseMocks();
             expect(request.getPathInfo()).andReturn(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
             expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn("text/plain");
-            String url = "http://pirx:9876/jolokia";
+            String url = "http://10.9.11.1:9876/jolokia";
             StringBuffer buf = new StringBuffer();
             buf.append(url).append(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
             expect(request.getRequestURL()).andReturn(buf);
@@ -259,7 +259,8 @@
         StringWriter sw = initRequestResponseMocks(
                 new Runnable() {
                     public void run() {
-                        expect(request.getHeader("Origin")).andReturn(null);
+                        expect(request.getHeader("Origin")).andStubReturn(null);
+                        expect(request.getHeader("Referer")).andStubReturn(null);
                         expect(request.getRemoteHost()).andReturn("localhost");
                         expect(request.getRemoteAddr()).andReturn("127.0.0.1");
                         expect(request.getRequestURI()).andReturn("/jolokia/");
@@ -368,7 +369,7 @@
         StringWriter sw = initRequestResponseMocks(
                 new Runnable() {
                     public void run() {
-                        expect(request.getHeader("Origin")).andReturn(in);
+                        expect(request.getHeader("Origin")).andStubReturn(in);
                         expect(request.getRemoteHost()).andReturn("localhost");
                         expect(request.getRemoteAddr()).andReturn("127.0.0.1");
                         expect(request.getRequestURI()).andReturn("/jolokia/");
@@ -464,8 +465,9 @@
         context.log(find("time:"));
         context.log(find("Response:"));
         context.log(find("TestDetector"),isA(RuntimeException.class));
-        expectLastCall().anyTimes();
-        replay(config, context);
+        expectLastCall().asStub();
+        replay(config, context);
+
         servlet.init(config);
 
         StringWriter sw = initRequestResponseMocks();
@@ -503,8 +505,8 @@
         HttpTestUtil.prepareServletContextMock(context, pContextParams);
 
 
-        expect(config.getServletContext()).andReturn(context).anyTimes();
-        expect(config.getServletName()).andReturn("jolokia").anyTimes();
+        expect(config.getServletContext()).andStubReturn(context);
+        expect(config.getServletName()).andStubReturn("jolokia");
         if (pExceptionClass != null) {
             context.log(find(pLogRegexp),isA(pExceptionClass));
         } else {
@@ -515,7 +517,7 @@
             }
         }
         context.log((String) anyObject());
-        expectLastCall().anyTimes();
+        expectLastCall().asStub();
         context.log(find("TestDetector"),isA(RuntimeException.class));
     }
 
@@ -569,7 +571,8 @@
     private Runnable getStandardRequestSetup() {
         return new Runnable() {
             public void run() {
-                expect(request.getHeader("Origin")).andReturn(null);
+                expect(request.getHeader("Origin")).andStubReturn(null);
+                expect(request.getHeader("Referer")).andStubReturn(null);
                 expect(request.getRemoteHost()).andReturn("localhost");
                 expect(request.getRemoteAddr()).andReturn("127.0.0.1");
                 expect(request.getRequestURI()).andReturn("/jolokia/");
```
