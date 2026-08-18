# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4174_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4174_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 93-133 of the vulnerable file.

        AccessAssertionTestUtil.setCreds("ROLE_USER", "ROLE_EDITOR");
        setUpConfigFiles();

        final MockHttpServletRequest servletCreateRequest = new MockHttpServletRequest();
        final MockHttpServletResponse servletCreateResponse = new MockHttpServletResponse();

        String requestData = loadRequestDataAsString();

        this.servlet.createReport("png", requestData, servletCreateRequest, servletCreateResponse);
        assertEquals(HttpStatus.OK.value(), servletCreateResponse.getStatus());
        final JSONObject response = new JSONObject(servletCreateResponse.getContentAsString());

        final String ref = response.getString(MapPrinterServlet.JSON_PRINT_JOB_REF);
        String statusURL = response.getString(MapPrinterServlet.JSON_STATUS_LINK);

        // wait until job is done
        boolean done = false;
        while (!done) {
            MockHttpServletRequest servletStatusRequest = new MockHttpServletRequest("GET", statusURL);
            MockHttpServletResponse servletStatusResponse = new MockHttpServletResponse();
            servlet.getStatus(ref, null, servletStatusRequest, servletStatusResponse);

            String contentAsString = servletStatusResponse.getContentAsString();

            final PJsonObject statusJson = parseJSONObjectFromString(contentAsString);
            assertTrue(statusJson.toString(), statusJson.has(MapPrinterServlet.JSON_DONE));

            done = statusJson.getBool(MapPrinterServlet.JSON_DONE);
            if (!done) {
                Thread.sleep(500);
            }
        }

        try {
            AccessAssertionTestUtil.setCreds("ROLE_USER");
            final MockHttpServletResponse getResponse1 = new MockHttpServletResponse();
            this.servlet.getReport(ref, false, getResponse1);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {
            // good
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
         while (!done) {
             MockHttpServletRequest servletStatusRequest = new MockHttpServletRequest("GET", statusURL);
             MockHttpServletResponse servletStatusResponse = new MockHttpServletResponse();
-            servlet.getStatus(ref, null, servletStatusRequest, servletStatusResponse);
+            servlet.getStatus(ref, servletStatusRequest, servletStatusResponse);
 
             String contentAsString = servletStatusResponse.getContentAsString();
 
```
