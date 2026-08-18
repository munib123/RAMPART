# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 24_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `24_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 247-287 of the vulnerable file.

    /**
     * OPTION requests are treated as CORS preflight requests
     *
     * @param req the original request
     * @param resp the response the answer are written to
     * */
    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Map<String,String> responseHeaders =
                requestHandler.handleCorsPreflightRequest(
                        req.getHeader("Origin"),
                        req.getHeader("Access-Control-Request-Headers"));
        for (Map.Entry<String,String> entry : responseHeaders.entrySet()) {
            resp.setHeader(entry.getKey(),entry.getValue());
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingThrowable", "PMD.AvoidInstanceofChecksInCatchClause" })
    private void handle(ServletRequestHandler pReqHandler,HttpServletRequest pReq, HttpServletResponse pResp) throws IOException {
        JSONAware json = null;
        try {
            // Check access policy
            requestHandler.checkAccess(allowDnsReverseLookup ? pReq.getRemoteHost() : null,
                                       pReq.getRemoteAddr(),
                                       getOriginOrReferer(pReq));

            // Remember the agent URL upon the first request. Needed for discovery
            updateAgentDetailsIfNeeded(pReq);

            // Dispatch for the proper HTTP request method
            json = handleSecurely(pReqHandler, pReq, pResp);
        } catch (Throwable exp) {
            json = requestHandler.handleThrowable(
                    exp instanceof RuntimeMBeanException ? ((RuntimeMBeanException) exp).getTargetException() : exp);
        } finally {
            setCorsHeader(pReq, pResp);

            if (json == null) {
                json = requestHandler.handleThrowable(new Exception("Internal error while handling an exception"));
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -264,20 +264,28 @@
     @SuppressWarnings({ "PMD.AvoidCatchingThrowable", "PMD.AvoidInstanceofChecksInCatchClause" })
     private void handle(ServletRequestHandler pReqHandler,HttpServletRequest pReq, HttpServletResponse pResp) throws IOException {
         JSONAware json = null;
+
         try {
             // Check access policy
             requestHandler.checkAccess(allowDnsReverseLookup ? pReq.getRemoteHost() : null,
                                        pReq.getRemoteAddr(),
                                        getOriginOrReferer(pReq));
 
+            // If a callback is given, check this is a valid javascript function name
+            validateCallbackIfGiven(pReq);
+
             // Remember the agent URL upon the first request. Needed for discovery
             updateAgentDetailsIfNeeded(pReq);
 
             // Dispatch for the proper HTTP request method
             json = handleSecurely(pReqHandler, pReq, pResp);
         } catch (Throwable exp) {
-            json = requestHandler.handleThrowable(
+            try {
+                json = requestHandler.handleThrowable(
                     exp instanceof RuntimeMBeanException ? ((RuntimeMBeanException) exp).getTargetException() : exp);
+            } catch (Throwable exp2) {
+                exp2.printStackTrace();
+            }
         } finally {
             setCorsHeader(pReq, pResp);
 
@@ -288,6 +296,7 @@
             sendResponse(pResp, pReq, json);
         }
     }
+
 
     private JSONAware handleSecurely(final ServletRequestHandler pReqHandler, final HttpServletRequest pReq, final HttpServletResponse pResp) throws IOException, PrivilegedActionException {
         Subject subject = (Subject) pReq.getAttribute(ConfigKey.JAAS_SUBJECT_REQUEST_ATTRIBUTE);
@@ -380,15 +389,6 @@
         }
     }
 
-    // Extract mime type for response (if not JSONP)
-    private String getMimeType(HttpServletRequest pReq) {
-        String requestMimeType = pReq.getParameter(ConfigKey.MIME_TYPE.getKeyValue());
-        if (requestMimeType != null) {
-            return requestMimeType;
-        }
-        return configMimeType;
-    }
-
     private boolean isStreamingEnabled(HttpServletRequest pReq) {
         String streamingFromReq = pReq.getParameter(ConfigKey.STREAMING.getKeyValue());
         if (streamingFromReq != null) {
@@ -470,8 +470,12 @@
 
     private void sendResponse(HttpServletResponse pResp, HttpServletRequest pReq, JSONAware pJson) throws IOException {
         String callback = pReq.getParameter(ConfigKey.CALLBACK.getKeyValue());
-        setContentType(pResp, callback != null ? "text/javascript" : getMimeType(pReq));
-
+
+        setContentType(pResp,
+                       MimeTypeUtil.getResponseMimeType(
+                           pReq.getParameter(ConfigKey.MIME_TYPE.getKeyValue()),
+                           configMimeType, callback
+                                                       ));
         pResp.setStatus(HttpServletResponse.SC_OK);
         setNoCacheHeaders(pResp);
         if (pJson == null) {
@@ -487,6 +491,12 @@
         }
     }
 
+    private void validateCallbackIfGiven(HttpServletRequest pReq) {
+        String callback = pReq.getParameter(ConfigKey.CALLBACK.getKeyValue());
+        if (callback != null && !MimeTypeUtil.isValidCallback(callback)) {
+            throw new IllegalArgumentException("Invalid callback name given, which must be a valid javascript function name");
+        }
+    }
     private void sendStreamingResponse(HttpServletResponse pResp, String pCallback, JSONStreamAware pJson) throws IOException {
         Writer writer = new OutputStreamWriter(pResp.getOutputStream(), "UTF-8");
         IoUtil.streamResponseAndClose(writer, pJson, pCallback);
```
