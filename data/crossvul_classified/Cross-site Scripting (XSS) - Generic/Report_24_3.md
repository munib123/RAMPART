# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 24_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `24_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 207-247 of the vulnerable file.

     */
    protected void checkAuthentication(HttpExchange pHttpExchange) throws SecurityException { }

    @SuppressWarnings({"PMD.AvoidCatchingThrowable", "PMD.AvoidInstanceofChecksInCatchClause"})
    public void doHandle(HttpExchange pExchange) throws IOException {
        if (requestHandler == null) {
            throw new IllegalStateException("Handler not yet started");
        }

        JSONAware json = null;
        URI uri = pExchange.getRequestURI();
        ParsedUri parsedUri = new ParsedUri(uri, context);
        try {
            // Check access policy
            InetSocketAddress address = pExchange.getRemoteAddress();
            requestHandler.checkAccess(getHostName(address),
                                       address.getAddress().getHostAddress(),
                                       extractOriginOrReferer(pExchange));
            String method = pExchange.getRequestMethod();

            // Dispatch for the proper HTTP request method
            if ("GET".equalsIgnoreCase(method)) {
                setHeaders(pExchange);
                json = executeGetRequest(parsedUri);
            } else if ("POST".equalsIgnoreCase(method)) {
                setHeaders(pExchange);
                json = executePostRequest(pExchange, parsedUri);
            } else if ("OPTIONS".equalsIgnoreCase(method)) {
                performCorsPreflightCheck(pExchange);
            } else {
                throw new IllegalArgumentException("HTTP Method " + method + " is not supported.");
            }
        } catch (Throwable exp) {
            json = requestHandler.handleThrowable(
                    exp instanceof RuntimeMBeanException ? ((RuntimeMBeanException) exp).getTargetException() : exp);
        } finally {
            sendResponse(pExchange, parsedUri, json);
        }
    }

    // ========================================================================
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,6 +224,9 @@
                                        extractOriginOrReferer(pExchange));
             String method = pExchange.getRequestMethod();
 
+            // If a callback is given, check this is a valid javascript function name
+            validateCallbackIfGiven(parsedUri);
+
             // Dispatch for the proper HTTP request method
             if ("GET".equalsIgnoreCase(method)) {
                 setHeaders(pExchange);
@@ -244,6 +247,14 @@
         }
     }
 
+
+    private void validateCallbackIfGiven(ParsedUri pUri) {
+        String callback = pUri.getParameter(ConfigKey.CALLBACK.getKeyValue());
+        if (callback != null && !MimeTypeUtil.isValidCallback(callback)) {
+            throw new IllegalArgumentException("Invalid callback name given, which must be a valid javascript function name");
+        }
+    }
+
     // ========================================================================
 
     // Used for checking origin or referer is an origin policy is enabled
@@ -342,10 +353,11 @@
         Headers headers = pExchange.getResponseHeaders();
         if (pJson != null) {
             headers.set("Content-Type", getMimeType(pParsedUri) + "; charset=utf-8");
-            String callback = pParsedUri.getParameter(ConfigKey.CALLBACK.getKeyValue());
             pExchange.sendResponseHeaders(200, 0);
             Writer writer = new OutputStreamWriter(pExchange.getResponseBody(), "UTF-8");
-            IoUtil.streamResponseAndClose(writer, pJson, callback);
+
+            String callback = pParsedUri.getParameter(ConfigKey.CALLBACK.getKeyValue());
+            IoUtil.streamResponseAndClose(writer, pJson, callback != null && MimeTypeUtil.isValidCallback(callback) ? callback : null);
         } else {
             headers.set("Content-Type", "text/plain");
             pExchange.sendResponseHeaders(200,-1);
@@ -360,7 +372,7 @@
                 headers.set("Content-Type", getMimeType(pParsedUri) + "; charset=utf-8");
                 String json = pJson.toJSONString();
                 String callback = pParsedUri.getParameter(ConfigKey.CALLBACK.getKeyValue());
-                String content = callback == null ? json : callback + "(" + json + ");";
+                String content = callback != null && MimeTypeUtil.isValidCallback(callback) ? callback + "(" + json + ");" : json;
                 byte[] response = content.getBytes("UTF8");
                 pExchange.sendResponseHeaders(200,response.length);
                 out = pExchange.getResponseBody();
@@ -380,16 +392,10 @@
 
     // Get the proper mime type according to configuration
     private String getMimeType(ParsedUri pParsedUri) {
-        if (pParsedUri.getParameter(ConfigKey.CALLBACK.getKeyValue()) != null) {
-            return "text/javascript";
-        } else {
-            String mimeType = pParsedUri.getParameter(ConfigKey.MIME_TYPE.getKeyValue());
-            if (mimeType != null) {
-                return mimeType;
-            }
-            mimeType = configuration.get(ConfigKey.MIME_TYPE);
-            return mimeType != null ? mimeType : ConfigKey.MIME_TYPE.getDefaultValue();
-        }
+        return MimeTypeUtil.getResponseMimeType(
+            pParsedUri.getParameter(ConfigKey.MIME_TYPE.getKeyValue()),
+            configuration.get(ConfigKey.MIME_TYPE),
+            pParsedUri.getParameter(ConfigKey.CALLBACK.getKeyValue()));
     }
 
     // Creat a log handler from either the given class or by creating a default log handler printing
```
