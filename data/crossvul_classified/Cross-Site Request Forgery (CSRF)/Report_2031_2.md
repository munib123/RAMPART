# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 2031_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2031_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 136-176 of the vulnerable file.

            JmxRequest jmxReq = JmxRequestFactory.createPostRequest((Map<String, ?>) jsonRequest,getProcessingParameter(pParameterMap));
            return executeRequest(jmxReq);
        } else {
            throw new IllegalArgumentException("Invalid JSON Request " + jsonRequest);
        }
    }

    /**
     * Handling an option request which is used for preflight checks before a CORS based browser request is
     * sent (for certain circumstances).
     *
     * See the <a href="http://www.w3.org/TR/cors/">CORS specification</a>
     * (section 'preflight checks') for more details.
     *
     * @param pOrigin the origin to check. If <code>null</code>, no headers are returned
     * @param pRequestHeaders extra headers to check against
     * @return headers to set
     */
    public Map<String, String> handleCorsPreflightRequest(String pOrigin, String pRequestHeaders) {
        Map<String,String> ret = new HashMap<String, String>();
        if (pOrigin != null && backendManager.isCorsAccessAllowed(pOrigin)) {
            // CORS is allowed, we set exactly the origin in the header, so there are no problems with authentication
            ret.put("Access-Control-Allow-Origin","null".equals(pOrigin) ? "*" : pOrigin);
            if (pRequestHeaders != null) {
                ret.put("Access-Control-Allow-Headers",pRequestHeaders);
            }
            // Fix for CORS with authentication (#104)
            ret.put("Access-Control-Allow-Credentials","true");
            // Allow for one year. Changes in access.xml are reflected directly in the  cors request itself
            ret.put("Access-Control-Allow-Max-Age","" + 3600 * 24 * 365);
        }
        return ret;
    }


    private Object extractJsonRequest(InputStream pInputStream, String pEncoding) throws IOException {
        InputStreamReader reader = null;
        try {
            reader =
                    pEncoding != null ?
                            new InputStreamReader(pInputStream, pEncoding) :
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,7 +153,7 @@
      */
     public Map<String, String> handleCorsPreflightRequest(String pOrigin, String pRequestHeaders) {
         Map<String,String> ret = new HashMap<String, String>();
-        if (pOrigin != null && backendManager.isCorsAccessAllowed(pOrigin)) {
+        if (pOrigin != null && backendManager.isOriginAllowed(pOrigin,false)) {
             // CORS is allowed, we set exactly the origin in the header, so there are no problems with authentication
             ret.put("Access-Control-Allow-Origin","null".equals(pOrigin) ? "*" : pOrigin);
             if (pRequestHeaders != null) {
@@ -277,15 +277,19 @@
      *
      * @param pHost host to check
      * @param pAddress address to check
-     */
-    public void checkClientIPAccess(String pHost, String pAddress) {
+     * @param pOrigin (optional) origin header to check also.
+     */
+    public void checkAccess(String pHost, String pAddress, String pOrigin) {
         if (!backendManager.isRemoteAccessAllowed(pHost,pAddress)) {
             throw new SecurityException("No access from client " + pAddress + " allowed");
         }
-    }
-
-    /**
-     * Check whether for the given host is a cross-browser request allowed. This check is deligated to the
+        if (pOrigin != null && !backendManager.isOriginAllowed(pOrigin,true)) {
+            throw new SecurityException("Origin " + pOrigin + " is not allowed to call this agent");
+        }
+    }
+
+    /**
+     * Check whether for the given host is a cross-browser request allowed. This check is delegated to the
      * backendmanager which is responsible for the security configuration.
      * Also, some sanity checks are applied.
      *
@@ -296,7 +300,7 @@
         if (pOrigin != null) {
             // Prevent HTTP response splitting attacks
             String origin  = pOrigin.replaceAll("[\\n\\r]*","");
-            if (backendManager.isCorsAccessAllowed(origin)) {
+            if (backendManager.isOriginAllowed(origin,false)) {
                 return "null".equals(origin) ? "*" : origin;
             } else {
                 return null;
```
