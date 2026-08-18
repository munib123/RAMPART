# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 284_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `284_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1286-1326 of the vulnerable file.

        );

        $this->setNextResponses($responses);

        $this->request('HEAD', '/', array(), array(), true);

        // https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13
        // "The Content-Length entity-header field indicates the size of the entity-body,
        // in decimal number of OCTETs, sent to the recipient or, in the case of the HEAD
        // method, the size of the entity-body that would have been sent had the request
        // been a GET."
        $this->assertEmpty($this->response->getContent());
        $this->assertEquals(12, $this->response->headers->get('Content-Length'));
    }

    public function testClientIpIsAlwaysLocalhostForForwardedRequests()
    {
        $this->setNextResponse();
        $this->request('GET', '/', array('REMOTE_ADDR' => '10.0.0.1'));

        $this->assertEquals('127.0.0.1', $this->kernel->getBackendRequest()->server->get('REMOTE_ADDR'));
    }

    /**
     * @dataProvider getTrustedProxyData
     */
    public function testHttpCacheIsSetAsATrustedProxy(array $existing, array $expected)
    {
        Request::setTrustedProxies($existing);

        $this->setNextResponse();
        $this->request('GET', '/', array('REMOTE_ADDR' => '10.0.0.1'));

        $this->assertEquals($expected, Request::getTrustedProxies());

        Request::setTrustedProxies(array());
    }

    public function getTrustedProxyData()
    {
        return array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1303,20 +1303,29 @@
         $this->setNextResponse();
         $this->request('GET', '/', array('REMOTE_ADDR' => '10.0.0.1'));
 
-        $this->assertEquals('127.0.0.1', $this->kernel->getBackendRequest()->server->get('REMOTE_ADDR'));
+        $that = $this;
+        $this->kernel->assert(function ($backendRequest) use ($that) {
+            $that->assertSame('127.0.0.1', $backendRequest->server->get('REMOTE_ADDR'));
+        });
     }
 
     /**
      * @dataProvider getTrustedProxyData
      */
-    public function testHttpCacheIsSetAsATrustedProxy(array $existing, array $expected)
+    public function testHttpCacheIsSetAsATrustedProxy(array $existing)
     {
         Request::setTrustedProxies($existing);
 
         $this->setNextResponse();
         $this->request('GET', '/', array('REMOTE_ADDR' => '10.0.0.1'));
-
-        $this->assertEquals($expected, Request::getTrustedProxies());
+        $this->assertSame($existing, Request::getTrustedProxies());
+
+        $that = $this;
+        $existing = array_unique(array_merge($existing, array('127.0.0.1')));
+        $this->kernel->assert(function ($backendRequest) use ($existing, $that) {
+            $that->assertSame($existing, Request::getTrustedProxies());
+            $that->assertsame('10.0.0.1', $backendRequest->getClientIp());
+        });
 
         Request::setTrustedProxies(array());
     }
@@ -1324,43 +1333,40 @@
     public function getTrustedProxyData()
     {
         return array(
-            array(array(), array('127.0.0.1')),
-            array(array('10.0.0.2'), array('10.0.0.2', '127.0.0.1')),
-            array(array('10.0.0.2', '127.0.0.1'), array('10.0.0.2', '127.0.0.1')),
+            array(array()),
+            array(array('10.0.0.2')),
+            array(array('10.0.0.2', '127.0.0.1')),
         );
     }
 
     /**
-     * @dataProvider getXForwardedForData
+     * @dataProvider getForwardedData
      */
-    public function testXForwarderForHeaderForForwardedRequests($xForwardedFor, $expected)
+    public function testForwarderHeaderForForwardedRequests($forwarded, $expected)
     {
         $this->setNextResponse();
         $server = array('REMOTE_ADDR' => '10.0.0.1');
-        if (false !== $xForwardedFor) {
-            $server['HTTP_X_FORWARDED_FOR'] = $xForwardedFor;
+        if (null !== $forwarded) {
+            Request::setTrustedProxies($server);
+            $server['HTTP_FORWARDED'] = $forwarded;
         }
         $this->request('GET', '/', $server);
 
-        $this->assertEquals($expected, $this->kernel->getBackendRequest()->headers->get('X-Forwarded-For'));
-    }
-
-    public function getXForwardedForData()
+        $that = $this;
+        $this->kernel->assert(function ($backendRequest) use ($expected, $that) {
+            $that->assertSame($expected, $backendRequest->headers->get('Forwarded'));
+        });
+
+        Request::setTrustedProxies(array());
+    }
+
+    public function getForwardedData()
     {
         return array(
-            array(false, '10.0.0.1'),
-            array('10.0.0.2', '10.0.0.2, 10.0.0.1'),
-            array('10.0.0.2, 10.0.0.3', '10.0.0.2, 10.0.0.3, 10.0.0.1'),
+            array(null, 'for="10.0.0.1";host="localhost";proto=http'),
+            array('for=10.0.0.2', 'for="10.0.0.2";host="localhost";proto=http, for="10.0.0.1"'),
+            array('for=10.0.0.2, for=10.0.0.3', 'for="10.0.0.2";host="localhost";proto=http, for="10.0.0.3", for="10.0.0.1"'),
         );
-    }
-
-    public function testXForwarderForHeaderForPassRequests()
-    {
-        $this->setNextResponse();
-        $server = array('REMOTE_ADDR' => '10.0.0.1');
-        $this->request('POST', '/', $server);
-
-        $this->assertEquals('10.0.0.1', $this->kernel->getBackendRequest()->headers->get('X-Forwarded-For'));
     }
 
     public function testEsiCacheRemoveValidationHeadersIfEmbeddedResponses()
```
