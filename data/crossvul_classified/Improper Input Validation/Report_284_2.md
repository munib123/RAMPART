# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 284_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `284_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 451-508 of the vulnerable file.

        }

        return $response;
    }

    /**
     * Forwards the Request to the backend and returns the Response.
     *
     * @param Request  $request A Request instance
     * @param bool     $catch   Whether to catch exceptions or not
     * @param Response $entry   A Response instance (the stale entry if present, null otherwise)
     *
     * @return Response A Response instance
     */
    protected function forward(Request $request, $catch = false, Response $entry = null)
    {
        if ($this->surrogate) {
            $this->surrogate->addSurrogateCapability($request);
        }

        // modify the X-Forwarded-For header if needed
        $forwardedFor = $request->headers->get('X-Forwarded-For');
        if ($forwardedFor) {
            $request->headers->set('X-Forwarded-For', $forwardedFor.', '.$request->server->get('REMOTE_ADDR'));
        } else {
            $request->headers->set('X-Forwarded-For', $request->server->get('REMOTE_ADDR'));
        }

        // fix the client IP address by setting it to 127.0.0.1 as HttpCache
        // is always called from the same process as the backend.
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // make sure HttpCache is a trusted proxy
        if (!\in_array('127.0.0.1', $trustedProxies = Request::getTrustedProxies())) {
            $trustedProxies[] = '127.0.0.1';
            Request::setTrustedProxies($trustedProxies);
        }

        // always a "master" request (as the real master request can be in cache)
        $response = $this->kernel->handle($request, HttpKernelInterface::MASTER_REQUEST, $catch);
        // FIXME: we probably need to also catch exceptions if raw === true

        // we don't implement the stale-if-error on Requests, which is nonetheless part of the RFC
        if (null !== $entry && \in_array($response->getStatusCode(), array(500, 502, 503, 504))) {
            if (null === $age = $entry->headers->getCacheControlDirective('stale-if-error')) {
                $age = $this->options['stale_if_error'];
            }

            if (abs($entry->getTtl()) < $age) {
                $this->record($request, 'stale-if-error');

                return $entry;
            }
        }

        $this->processResponseBody($request, $response);

        if ($this->isPrivateRequest($request) && !$response->headers->hasCacheControlDirective('public')) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -468,27 +468,8 @@
             $this->surrogate->addSurrogateCapability($request);
         }
 
-        // modify the X-Forwarded-For header if needed
-        $forwardedFor = $request->headers->get('X-Forwarded-For');
-        if ($forwardedFor) {
-            $request->headers->set('X-Forwarded-For', $forwardedFor.', '.$request->server->get('REMOTE_ADDR'));
-        } else {
-            $request->headers->set('X-Forwarded-For', $request->server->get('REMOTE_ADDR'));
-        }
-
-        // fix the client IP address by setting it to 127.0.0.1 as HttpCache
-        // is always called from the same process as the backend.
-        $request->server->set('REMOTE_ADDR', '127.0.0.1');
-
-        // make sure HttpCache is a trusted proxy
-        if (!\in_array('127.0.0.1', $trustedProxies = Request::getTrustedProxies())) {
-            $trustedProxies[] = '127.0.0.1';
-            Request::setTrustedProxies($trustedProxies);
-        }
-
         // always a "master" request (as the real master request can be in cache)
-        $response = $this->kernel->handle($request, HttpKernelInterface::MASTER_REQUEST, $catch);
-        // FIXME: we probably need to also catch exceptions if raw === true
+        $response = SubRequestHandler::handle($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $catch);
 
         // we don't implement the stale-if-error on Requests, which is nonetheless part of the RFC
         if (null !== $entry && \in_array($response->getStatusCode(), array(500, 502, 503, 504))) {
```
