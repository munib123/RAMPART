# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2462_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2462_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 480-520 of the vulnerable file.


    public function testPrepareDoesNothingIfContentTypeIsSet()
    {
        $response = new Response('foo');
        $response->headers->set('Content-Type', 'text/plain');

        $response->prepare(new Request());

        $this->assertEquals('text/plain; charset=UTF-8', $response->headers->get('content-type'));
    }

    public function testPrepareDoesNothingIfRequestFormatIsNotDefined()
    {
        $response = new Response('foo');

        $response->prepare(new Request());

        $this->assertEquals('text/html; charset=UTF-8', $response->headers->get('content-type'));
    }

    public function testPrepareSetContentType()
    {
        $response = new Response('foo');
        $request = Request::create('/');
        $request->setRequestFormat('json');
        $request->headers->remove('accept');

        $response->prepare($request);

        $this->assertEquals('application/json', $response->headers->get('content-type'));
    }

    public function testPrepareRemovesContentForHeadRequests()
    {
        $response = new Response('foo');
        $request = Request::create('/', 'HEAD');

        $length = 12345;
        $response->headers->set('Content-Length', $length);
        $response->prepare($request);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -497,12 +497,25 @@
         $this->assertEquals('text/html; charset=UTF-8', $response->headers->get('content-type'));
     }
 
+    /**
+     * Same URL cannot produce different Content-Type based on the value of the Accept header,
+     * unless explicitly stated in the response object.
+     */
+    public function testPrepareDoesNotSetContentTypeBasedOnRequestAcceptHeader()
+    {
+        $response = new Response('foo');
+        $request = Request::create('/');
+        $request->headers->set('Accept', 'application/json');
+        $response->prepare($request);
+
+        $this->assertSame('text/html; charset=UTF-8', $response->headers->get('content-type'));
+    }
+
     public function testPrepareSetContentType()
     {
         $response = new Response('foo');
         $request = Request::create('/');
         $request->setRequestFormat('json');
-        $request->headers->remove('accept');
 
         $response->prepare($request);
 
```
