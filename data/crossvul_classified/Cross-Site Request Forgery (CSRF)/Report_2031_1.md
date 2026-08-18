# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 261-301 of the vulnerable file.

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
            requestHandler.checkClientIPAccess(pReq.getRemoteHost(),pReq.getRemoteAddr());

            // Remember the agent URL upon the first request. Needed for discovery
            updateAgentUrlIfNeeded(pReq);

            // Dispatch for the proper HTTP request method
            json = pReqHandler.handleRequest(pReq,pResp);
        } catch (Throwable exp) {
            json = requestHandler.handleThrowable(
                    exp instanceof RuntimeMBeanException ? ((RuntimeMBeanException) exp).getTargetException() : exp);
        } finally {
            setCorsHeader(pReq, pResp);

            String callback = pReq.getParameter(ConfigKey.CALLBACK.getKeyValue());
            String answer = json != null ?
                    json.toJSONString() :
                    requestHandler.handleThrowable(new Exception("Internal error while handling an exception")).toJSONString();
            if (callback != null) {
                // Send a JSONP response
                sendResponse(pResp, "text/javascript", callback + "(" + answer + ");");
            } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -278,7 +278,8 @@
         JSONAware json = null;
         try {
             // Check access policy
-            requestHandler.checkClientIPAccess(pReq.getRemoteHost(),pReq.getRemoteAddr());
+            requestHandler.checkAccess(pReq.getRemoteHost(), pReq.getRemoteAddr(),
+                                       getOriginOrReferer(pReq));
 
             // Remember the agent URL upon the first request. Needed for discovery
             updateAgentUrlIfNeeded(pReq);
@@ -303,6 +304,15 @@
             }
         }
     }
+
+    private String getOriginOrReferer(HttpServletRequest pReq) {
+        String origin = pReq.getHeader("Origin");
+        if (origin == null) {
+            origin = pReq.getHeader("Referer");
+        }
+        return origin != null ? origin.replaceAll("[\\n\\r]*","") : null;
+    }
+
 
     // Update the agent URL in the agent details if not already done
     private void updateAgentUrlIfNeeded(HttpServletRequest pReq) {
```
