# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in scala
**Pair ID:** 4646_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4646_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```scala
Lines 64-104 of the vulnerable file.

        addHeader(sessionConfig.csrfSubmittedName, "something else") ~>
        routes ~>
        check {
          rejections should be(List(AuthorizationFailedRejection))
        }
    }
  }

  it should "reject requests if the csrf cookie isn't set" in {
    Get("/site") ~> routes ~> check {
      responseAs[String] should be("ok")

      Post("/transfer_money") ~>
        routes ~>
        check {
          rejections should be(List(AuthorizationFailedRejection))
        }
    }
  }

  it should "accept requests if the csrf cookie matches the header value" in {
    Get("/site") ~> routes ~> check {
      responseAs[String] should be("ok")
      val Some(csrfCookie) = header[`Set-Cookie`]

      Post("/transfer_money") ~>
        addHeader(Cookie(cookieName, csrfCookie.cookie.value)) ~>
        addHeader(sessionConfig.csrfSubmittedName, csrfCookie.cookie.value) ~>
        routes ~>
        check {
          responseAs[String] should be("ok")
        }
    }
  }

  it should "accept requests if the csrf cookie matches the form field value" in {
    val testRoutes = routes(manager, checkHeaderAndForm)
    Get("/site") ~> testRoutes ~> check {
      responseAs[String] should be("ok")
      val Some(csrfCookie) = header[`Set-Cookie`]

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,20 @@
     }
   }
 
+  it should "reject requests if the csrf cookie and the header are empty" in {
+    Get("/site") ~> routes ~> check {
+      responseAs[String] should be("ok")
+
+      Post("/transfer_money") ~>
+        addHeader(Cookie(cookieName, "")) ~>
+        addHeader(sessionConfig.csrfSubmittedName, "") ~>
+        routes ~>
+        check {
+          rejections should be(List(AuthorizationFailedRejection))
+        }
+    }
+  }
+
   it should "accept requests if the csrf cookie matches the header value" in {
     Get("/site") ~> routes ~> check {
       responseAs[String] should be("ok")
```
