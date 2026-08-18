# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in c
**Pair ID:** 1392_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1392_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```c
Lines 908-948 of the vulnerable file.


/*
 * Check that a URL is safe for redirect.
 *
 * Parameters:
 *  request_rec *r       The request we are processing.
 *  const char *url      The URL we should check.
 *
 * Returns:
 *  OK on success, HTTP_BAD_REQUEST otherwise.
 */
int am_check_url(request_rec *r, const char *url)
{
    const char *i;

    for (i = url; *i; i++) {
        if (*i >= 0 && *i < ' ') {
            /* Deny all control-characters. */
            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, HTTP_BAD_REQUEST, r,
                          "Control character detected in URL.");
            return HTTP_BAD_REQUEST;
        }
    }

    return OK;
}

/* This function generates a given number of (pseudo)random bytes.
 * The current implementation uses OpenSSL's RAND_*-functions.
 *
 * Parameters:
 *  request_rec *r       The request we are generating random bytes for.
 *                       The request is used for configuration and
 *                       error/warning reporting.
 *  void *dest           The address if the buffer we should fill with data.
 *  apr_size_t count     The number of random bytes to create.
 *
 * Returns:
 *  OK on success, or HTTP_INTERNAL_SERVER on failure.
 */
int am_generate_random_bytes(request_rec *r, void *dest, apr_size_t count)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -925,6 +925,13 @@
             /* Deny all control-characters. */
             AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, HTTP_BAD_REQUEST, r,
                           "Control character detected in URL.");
+            return HTTP_BAD_REQUEST;
+        }
+        if (*i == '\\') {
+            /* Reject backslash character, as it can be used to bypass
+             * redirect URL validation. */
+            AM_LOG_RERROR(APLOG_MARK, APLOG_ERR, HTTP_BAD_REQUEST, r,
+                          "Backslash character detected in URL.");
             return HTTP_BAD_REQUEST;
         }
     }
```
