# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 4646_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4646_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 119-159 of the vulnerable file.

        TestRouteResult testRouteResult = testRoute(route)
            .run(HttpRequest.GET("/site"));

        // then
        testRouteResult
            .assertStatusCode(StatusCodes.OK);

        /* second request */
        // when
        TestRouteResult testRouteResult2 = testRoute(route)
            .run(HttpRequest.POST("/transfer_money"));

        // then
        testRouteResult2
            .assertStatusCode(StatusCodes.FORBIDDEN);


    }

    @Test
    public void shouldAcceptRequestsIfTheCsrfCookieMatchesTheHeaderValue() {
        // given
        final Route route = createCsrfRouteWithCheckHeaderMode();

        // when
        TestRouteResult testRouteResult = testRoute(route)
            .run(HttpRequest.GET("/site"));

        // then
        testRouteResult
            .assertStatusCode(StatusCodes.OK);

        // and
        HttpCookie csrfCookie = getCsrfTokenCookieValues(testRouteResult.response());

        /* second request */
        // when
        TestRouteResult testRouteResult2 = testRoute(route)
            .run(HttpRequest.POST("/transfer_money")
                .addHeader(Cookie.create(csrfCookieName, csrfCookie.value()))
                .addHeader(RawHeader.create(csrfSubmittedName, csrfCookie.value()))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,33 @@
     }
 
     @Test
+    public void shouldRejectRequestsIfTheCsrfCookieAndTheHeaderAreEmpty() {
+        // given
+        final Route route = createCsrfRouteWithCheckHeaderMode();
+
+        // when
+        TestRouteResult testRouteResult = testRoute(route)
+          .run(HttpRequest.GET("/site"));
+
+        // then
+        testRouteResult
+          .assertStatusCode(StatusCodes.OK);
+
+        /* second request */
+        // when
+        TestRouteResult testRouteResult2 = testRoute(route)
+          .run(HttpRequest.POST("/transfer_money")
+            .addHeader(Cookie.create(csrfCookieName, ""))
+            .addHeader(RawHeader.create(csrfSubmittedName, ""))
+          );
+
+        // then
+        testRouteResult2
+          .assertStatusCode(StatusCodes.FORBIDDEN);
+
+    }
+
+    @Test
     public void shouldAcceptRequestsIfTheCsrfCookieMatchesTheHeaderValue() {
         // given
         final Route route = createCsrfRouteWithCheckHeaderMode();
```
