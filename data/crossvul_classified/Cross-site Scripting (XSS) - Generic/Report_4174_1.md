# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4174_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4174_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 104-144 of the vulnerable file.

     * The url path to create a print task and to get a finished print.
     */
    public static final String REPORT_URL = "/report";
    /**
     * The url path to get the list of fonts available to geotools.
     */
    public static final String FONTS_URL = "/fonts";
    /**
     * The key containing an error message for failed jobs.
     */
    public static final String JSON_ERROR = "error";
    /**
     * The application ID which indicates the configuration file to load.
     */
    public static final String JSON_APP = "app";

    /* Registry keys */
    /**
     * If the job is done (value is true) or not (value is false).
     *
     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)} response.
     */
    public static final String JSON_DONE = "done";
    /**
     * The status of the job. One of the following values:
     * <ul>
     * <li>waiting</li>
     * <li>running</li>
     * <li>finished</li>
     * <li>cancelled</li>
     * <li>error</li>
     * </ul>
     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)} response
     */
    public static final String JSON_STATUS = "status";
    /**
     * The elapsed time in ms from the point the job started. If the job is finished, this is the duration it
     * took to process the job.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,7 @@
     /**
      * If the job is done (value is true) or not (value is false).
      *
-     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
+     * Part of the {@link #getStatus(String, javax.servlet.http.HttpServletRequest,
      * javax.servlet.http.HttpServletResponse)} response.
      */
     public static final String JSON_DONE = "done";
@@ -134,7 +134,7 @@
      * <li>cancelled</li>
      * <li>error</li>
      * </ul>
-     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
+     * Part of the {@link #getStatus(String, javax.servlet.http.HttpServletRequest,
      * javax.servlet.http.HttpServletResponse)} response
      */
     public static final String JSON_STATUS = "status";
@@ -142,14 +142,14 @@
      * The elapsed time in ms from the point the job started. If the job is finished, this is the duration it
      * took to process the job.
      *
-     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
+     * Part of the {@link #getStatus(String, javax.servlet.http.HttpServletRequest,
      * javax.servlet.http.HttpServletResponse)} response.
      */
     public static final String JSON_ELAPSED_TIME = "elapsedTime";
     /**
      * A rough estimate for the time in ms the job still has to wait in the queue until it starts processing.
      *
-     * Part of the {@link #getStatus(String, String, javax.servlet.http.HttpServletRequest,
+     * Part of the {@link #getStatus(String, javax.servlet.http.HttpServletRequest,
      * javax.servlet.http.HttpServletResponse)} response.
      */
     public static final String JSON_WAITING_TIME = "waitingTime";
@@ -271,7 +271,8 @@
     private static String maybeAddRequestId(final String ref, final HttpServletRequest request) {
         final Optional<String> headerName =
                 REQUEST_ID_HEADERS.stream().filter(h -> request.getHeader(h) != null).findFirst();
-        return headerName.map(s -> ref + "@" + request.getHeader(s).replaceAll("[^a-zA-Z0-9._:-]", "_")
+        return headerName.map(
+            s -> ref + "@" + request.getHeader(s).replaceAll("[^a-zA-Z0-9._:-]", "_")
         ).orElse(ref);
     }
 
@@ -284,7 +285,6 @@
      *
      * @param appId the app ID
      * @param referenceId the job reference
-     * @param jsonpCallback if given the result is returned with a function call wrapped around it
      * @param statusRequest the request object
      * @param statusResponse the response object
      */
@@ -292,10 +292,9 @@
     public final void getStatusSpecificAppId(
             @SuppressWarnings("unused") @PathVariable final String appId,
             @PathVariable final String referenceId,
-            @RequestParam(value = "jsonp", defaultValue = "") final String jsonpCallback,
             final HttpServletRequest statusRequest,
             final HttpServletResponse statusResponse) {
-        getStatus(referenceId, jsonpCallback, statusRequest, statusResponse);
+        getStatus(referenceId, statusRequest, statusResponse);
     }
 
     /**
@@ -306,14 +305,12 @@
      * </code></pre>
      *
      * @param referenceId the job reference
-     * @param jsonpCallback if given the result is returned with a function call wrapped around it
      * @param statusRequest the request object
      * @param statusResponse the response object
      */
     @RequestMapping(value = STATUS_URL + "/{referenceId:\\S+}.json", method = RequestMethod.GET)
     public final void getStatus(
             @PathVariable final String referenceId,
-            @RequestParam(value = "jsonp", defaultValue = "") final String jsonpCallback,
             final HttpServletRequest statusRequest,
             final HttpServletResponse statusResponse) {
         MDC.put(Processor.MDC_JOB_ID_KEY, referenceId);
@@ -321,10 +318,8 @@
         try {
             PrintJobStatus status = this.jobManager.getStatus(referenceId);
 
-            setContentType(statusResponse, jsonpCallback);
+            setContentType(statusResponse);
             try (PrintWriter writer = statusResponse.getWriter()) {
-
-                appendJsonpCallback(jsonpCallback, writer);
                 JSONWriter json = new JSONWriter(writer);
                 json.object();
                 {
@@ -339,7 +334,6 @@
                     addDownloadLinkToJson(statusRequest, referenceId, json);
                 }
                 json.endObject();
-                appendJsonpCallbackEnd(jsonpCallback, writer);
             }
         } catch (JSONException | IOException e) {
             throw ExceptionUtils.getRuntimeException(e);
@@ -638,22 +632,18 @@
     /**
      * To get (in JSON) the information about the available formats and CO.
      *
-     * @param jsonpCallback if given the result is returned with a function call wrapped around it
      * @param listAppsResponse the response object
      */
     @RequestMapping(value = LIST_APPS_URL, method = RequestMethod.GET)
     public final void listAppIds(
-            @RequestParam(value = "jsonp", defaultValue = "") final String jsonpCallback,
             final HttpServletResponse listAppsResponse) throws ServletException,
             IOException {
         MDC.remove(Processor.MDC_JOB_ID_KEY);
         setCache(listAppsResponse);
         Set<String> appIds = this.printerFactory.getAppIds();
 
-        setContentType(listAppsResponse, jsonpCallback);
+        setContentType(listAppsResponse);
         try (PrintWriter writer = listAppsResponse.getWriter()) {
-            appendJsonpCallback(jsonpCallback, writer);
-
             JSONWriter json = new JSONWriter(writer);
             try {
                 json.array();
@@ -664,8 +654,6 @@
             } catch (JSONException e) {
                 throw new ServletException(e);
             }
-
-            appendJsonpCallbackEnd(jsonpCallback, writer);
         }
     }
 
@@ -673,18 +661,16 @@
      * To get (in JSON) the information about the available formats and CO.
      *
      * @param pretty if true then pretty print the capabilities
-     * @param jsonpCallback if given the result is returned with a function call wrapped around it
      * @param request the request
      * @param capabilitiesResponse the response object
      */
     @RequestMapping(value = CAPABILITIES_URL, method = RequestMethod.GET)
     public final void getCapabilities(
             @RequestParam(value = "pretty", defaultValue = "false") final boolean pretty,
-            @RequestParam(value = "jsonp", defaultValue = "") final String jsonpCallback,
             final HttpServletRequest request,
             final HttpServletResponse capabilitiesResponse) throws ServletException,
             IOException {
-        getCapabilities(DEFAULT_CONFIGURATION_FILE_KEY, pretty, jsonpCallback, request, capabilitiesResponse);
+        getCapabilities(DEFAULT_CONFIGURATION_FILE_KEY, pretty, request, capabilitiesResponse);
     }
 
     /**
@@ -693,7 +679,6 @@
      * @param appId the name of the "app" or in other words, a mapping to the configuration file for
      *         this request.
      * @param pretty if true then pretty print the capabilities
-     * @param jsonpCallback if given the result is returned with a function call wrapped around it
      * @param request the request
      * @param capabilitiesResponse the response object
      */
@@ -701,7 +686,6 @@
     public final void getCapabilities(
             @PathVariable final String appId,
             @RequestParam(value = "pretty", defaultValue = "false") final boolean pretty,
-            @RequestParam(value = "jsonp", defaultValue = "") final String jsonpCallback,
             final HttpServletRequest request,
             final HttpServletResponse capabilitiesResponse) throws ServletException,
             IOException {
@@ -719,16 +703,12 @@
             return;
         }
 
-        setContentType(capabilitiesResponse, jsonpCallback);
... (diff truncated)
```
