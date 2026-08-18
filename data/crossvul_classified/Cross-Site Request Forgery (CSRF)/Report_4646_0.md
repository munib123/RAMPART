# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in scala
**Pair ID:** 4646_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4646_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```scala
Lines 6-46 of the vulnerable file.


trait CsrfDirectives {

  /**
    * Protects against CSRF attacks using a double-submit cookie. The cookie will be set on any `GET` request which
    * doesn't have the token set in the header. For all other requests, the value of the token from the CSRF cookie must
    * match the value in the custom header (or request body, if `checkFormBody` is `true`).
    *
    * Note that this scheme can be broken when not all subdomains are protected or not using HTTPS and secure cookies,
    * and the token is placed in the request body (not in the header).
    *
    * See the documentation for more details.
    */
  def randomTokenCsrfProtection[T](checkMode: CsrfCheckMode[T]): Directive0 = {
    csrfTokenFromCookie(checkMode).flatMap {
      case Some(cookie) =>
        // if a cookie is already set, we let through all get requests (without setting a new token), or validate
        // that the token matches.
        get.recover { _ =>
          submittedCsrfToken(checkMode).flatMap { submitted =>
            if (submitted == cookie) {
              pass
            } else {
              reject(checkMode.csrfManager.tokenInvalidRejection).toDirective[Unit]
            }
          }
        }
      case None =>
        // if a cookie is not set, generating a new one for get requests, rejecting other
        (get & setNewCsrfToken(checkMode)).recover(_ => reject(checkMode.csrfManager.tokenInvalidRejection))
    }
  }

  def submittedCsrfToken[T](checkMode: CsrfCheckMode[T]): Directive1[String] = {
    headerValueByName(checkMode.manager.config.csrfSubmittedName).recover { rejections =>
      checkMode match {
        case c: CheckHeaderAndForm[T] =>
          import c.materializer
          formField(checkMode.manager.config.csrfSubmittedName)
        case _ => reject(rejections: _*)
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,7 @@
         // that the token matches.
         get.recover { _ =>
           submittedCsrfToken(checkMode).flatMap { submitted =>
-            if (submitted == cookie) {
+            if (submitted == cookie && !cookie.isEmpty) {
               pass
             } else {
               reject(checkMode.csrfManager.tokenInvalidRejection).toDirective[Unit]
```
