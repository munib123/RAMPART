# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in typescript
**Pair ID:** 3901_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3901_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```typescript
Lines 369-409 of the vulnerable file.

        const redirectUrl: string | null = response.message.headers['location']
        if (!redirectUrl) {
          // if there's no location to redirect to, we won't
          break
        }
        let parsedRedirectUrl = url.parse(redirectUrl)
        if (
          parsedUrl.protocol == 'https:' &&
          parsedUrl.protocol != parsedRedirectUrl.protocol &&
          !this._allowRedirectDowngrade
        ) {
          throw new Error(
            'Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.'
          )
        }

        // we need to finish reading the response before reassigning response
        // which will leak the open socket.
        await response.readBody()

        // let's make the request with the new redirectUrl
        info = this._prepareRequest(verb, parsedRedirectUrl, headers)
        response = await this.requestRaw(info, data)
        redirectsRemaining--
      }

      if (HttpResponseRetryCodes.indexOf(response.message.statusCode) == -1) {
        // If not a retry code, return immediately instead of retrying
        return response
      }

      numTries += 1

      if (numTries < maxTries) {
        await response.readBody()
        await this._performExponentialBackoff(numTries)
      }
    }

    return response
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -386,6 +386,16 @@
         // which will leak the open socket.
         await response.readBody()
 
+        // strip authorization header if redirected to a different hostname
+        if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
+          for (let header in headers) {
+            // header names are case insensitive
+            if (header.toLowerCase() === 'authorization') {
+              delete headers[header]
+            }
+          }
+        }
+
         // let's make the request with the new redirectUrl
         info = this._prepareRequest(verb, parsedRedirectUrl, headers)
         response = await this.requestRaw(info, data)
```
