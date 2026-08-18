# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 24_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `24_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 96-136 of the vulnerable file.

        response = createMock(HttpServletResponse.class);
        initConfigMocks(new String[] {ConfigKey.AGENT_CONTEXT.getKeyValue(),"/jmx4perl",ConfigKey.MAX_DEPTH.getKeyValue(),"10"},
                        new String[] {ConfigKey.AGENT_CONTEXT.getKeyValue(),"/j0l0k14",ConfigKey.MAX_OBJECTS.getKeyValue(),"20",
                                      ConfigKey.CALLBACK.getKeyValue(),"callback is a request option, must be empty here"},
                        null,null);
        replay(config, context,request,response);

        servlet.init(config);
        servlet.destroy();

        org.jolokia.config.Configuration cfg = servlet.initConfig(config);
        assertEquals(cfg.get(ConfigKey.AGENT_CONTEXT), "/j0l0k14");
        assertEquals(cfg.get(ConfigKey.MAX_DEPTH), "10");
        assertEquals(cfg.get(ConfigKey.MAX_OBJECTS), "20");
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

        expect(config.getServletContext()).andStubReturn(context);
        expect(config.getServletName()).andStubReturn("jolokia");
        replay(config, context);

        servlet.init(config);
        servlet.destroy();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,7 +113,7 @@
     }
 
     @Test
-    public void initWithcustomAccessRestrictor() throws ServletException {
+    public void initWithCustomAccessRestrictor() throws ServletException {
         prepareStandardInitialisation();
         servlet.destroy();
     }
@@ -248,6 +248,44 @@
         servlet.doGet(request, response);
 
         assertTrue(sw.toString().contains("used"));
+        servlet.destroy();
+    }
+
+    @Test
+    public void simpleGetWithWrongMimeType() throws ServletException, IOException {
+        checkMimeTypes("text/html", "text/plain");
+    }
+
+    @Test
+    public void simpleGetWithTextPlainMimeType() throws ServletException, IOException {
+        checkMimeTypes("text/plain", "text/plain");
+    }
+
+    @Test
+    public void simpleGetWithApplicationJsonMimeType() throws ServletException, IOException {
+        checkMimeTypes("application/json", "application/json");
+    }
+
+    private void checkMimeTypes(String given, final String expected) throws ServletException, IOException {
+        prepareStandardInitialisation();
+
+        initRequestResponseMocks(
+            getStandardRequestSetup(),
+            new Runnable() {
+                public void run() {
+                    response.setCharacterEncoding("utf-8");
+                    // The default content type
+                    response.setContentType(expected);
+                    response.setStatus(200);
+                }
+            });
+        expect(request.getPathInfo()).andReturn(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
+        expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn(given);
+        replay(request, response);
+
+        servlet.doGet(request, response);
+
+        verifyMocks();
         servlet.destroy();
     }
 
@@ -484,12 +522,37 @@
                 });
         expect(request.getPathInfo()).andReturn(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
         expect(request.getAttribute("subject")).andReturn(null);
+        expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn(null);
 
         replay(request, response);
 
         servlet.doGet(request, response);
 
         assertTrue(sw.toString().matches("^myCallback\\(.*\\);$"));
+        servlet.destroy();
+    }
+
+    @Test
+    public void withInvalidCallback() throws IOException, ServletException {
+        servlet = new AgentServlet(new AllowAllRestrictor());
+        initConfigMocks(null, null,"Error 400", IllegalArgumentException.class);
+        replay(config, context);
+        servlet.init(config);
+        ByteArrayOutputStream sw = initRequestResponseMocks(
+            "doSomethingEvil(); myCallback",
+            getStandardRequestSetup(),
+            getStandardResponseSetup());
+        expect(request.getPathInfo()).andReturn(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
+        expect(request.getAttribute("subject")).andReturn(null);
+        expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn(null);
+
+        replay(request, response);
+
+        servlet.doGet(request, response);
+        String resp = sw.toString();
+        assertTrue(resp.contains("error_type"));
+        assertTrue(resp.contains("IllegalArgumentException"));
+        assertTrue(resp.matches(".*status.*400.*"));
         servlet.destroy();
     }
 
@@ -606,7 +669,7 @@
         response = createMock(HttpServletResponse.class);
         setNoCacheHeaders(response);
 
-        expect(request.getParameter(ConfigKey.CALLBACK.getKeyValue())).andReturn(callback);
+        expect(request.getParameter(ConfigKey.CALLBACK.getKeyValue())).andReturn(callback).anyTimes();
         requestSetup.run();
         responseSetup.run();
 
@@ -648,6 +711,7 @@
         return new Runnable() {
             public void run() {
                 response.setCharacterEncoding("utf-8");
+                // The default content type
                 response.setContentType("text/plain");
                 response.setStatus(200);
             }
@@ -690,7 +754,7 @@
                 expect(request.getAttribute(ConfigKey.JAAS_SUBJECT_REQUEST_ATTRIBUTE)).andReturn(null);
 
                 expect(request.getPathInfo()).andReturn(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
-                expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn("text/plain");
+                expect(request.getParameter(ConfigKey.MIME_TYPE.getKeyValue())).andReturn("text/plain").anyTimes();
                 StringBuffer buf = new StringBuffer();
                 buf.append(url).append(HttpTestUtil.HEAP_MEMORY_GET_REQUEST);
                 expect(request.getRequestURL()).andReturn(buf);
```
