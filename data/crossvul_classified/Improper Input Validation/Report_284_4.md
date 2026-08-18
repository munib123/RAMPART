# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 284_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `284_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel\Tests\Fragment;

use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Controller\ControllerReference;
use Symfony\Component\HttpKernel\Fragment\InlineFragmentRenderer;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\HttpKernel\KernelEvents;

class InlineFragmentRendererTest extends TestCase
{
    private $originalTrustedHeaderName;

    protected function setUp()
    {
        $this->originalTrustedHeaderName = Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP);
    }

    protected function tearDown()
    {
        Request::setTrustedHeaderName(Request::HEADER_CLIENT_IP, $this->originalTrustedHeaderName);
    }

    public function testRender()
    {
        $strategy = new InlineFragmentRenderer($this->getKernel($this->returnValue(new Response('foo'))));

        $this->assertEquals('foo', $strategy->render('/', Request::create('/'))->getContent());
    }

    public function testRenderWithControllerReference()
    {
        $strategy = new InlineFragmentRenderer($this->getKernel($this->returnValue(new Response('foo'))));

        $this->assertEquals('foo', $strategy->render(new ControllerReference('main_controller', array(), array()), Request::create('/'))->getContent());
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,12 +26,16 @@
 
     protected function setUp()
     {
-        $this->originalTrustedHeaderName = Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP);
+        $this->originalTrustedHeaderNames = array(
+            Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP),
+            Request::getTrustedHeaderName(Request::HEADER_FORWARDED),
+        );
     }
 
     protected function tearDown()
     {
-        Request::setTrustedHeaderName(Request::HEADER_CLIENT_IP, $this->originalTrustedHeaderName);
+        Request::setTrustedHeaderName(Request::HEADER_CLIENT_IP, $this->originalTrustedHeaderNames[0]);
+        Request::setTrustedHeaderName(Request::HEADER_FORWARDED, $this->originalTrustedHeaderNames[1]);
     }
 
     public function testRender()
@@ -55,7 +59,7 @@
         $subRequest = Request::create('/_fragment?_path=_format%3Dhtml%26_locale%3Den%26_controller%3Dmain_controller');
         $subRequest->attributes->replace(array('object' => $object, '_format' => 'html', '_controller' => 'main_controller', '_locale' => 'en'));
         $subRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
-        $subRequest->server->set('HTTP_X_FORWARDED_FOR', '127.0.0.1');
+        $subRequest->headers->set('forwarded', array('for="127.0.0.1";host="localhost";proto=http'));
 
         $strategy = new InlineFragmentRenderer($this->getKernelExpectingRequest($subRequest));
 
@@ -83,8 +87,12 @@
     public function testRenderWithTrustedHeaderDisabled()
     {
         Request::setTrustedHeaderName(Request::HEADER_CLIENT_IP, '');
-
-        $strategy = new InlineFragmentRenderer($this->getKernelExpectingRequest(Request::create('/')));
+        Request::setTrustedHeaderName(Request::HEADER_FORWARDED, '');
+
+        $expectedSubRequest = Request::create('/');
+        $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
+
+        $strategy = new InlineFragmentRenderer($this->getKernelExpectingRequest($expectedSubRequest));
         $this->assertSame('foo', $strategy->render('/', Request::create('/'))->getContent());
     }
 
@@ -168,11 +176,10 @@
     {
         $expectedSubRequest = Request::create('/');
         $expectedSubRequest->headers->set('Surrogate-Capability', 'abc="ESI/1.0"');
-
         if (Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP)) {
             $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
-            $expectedSubRequest->server->set('HTTP_X_FORWARDED_FOR', '127.0.0.1');
         }
+        $expectedSubRequest->headers->set('forwarded', array('for="127.0.0.1";host="localhost";proto=http'));
 
         $strategy = new InlineFragmentRenderer($this->getKernelExpectingRequest($expectedSubRequest));
 
@@ -194,10 +201,8 @@
     public function testHeadersPossiblyResultingIn304AreNotAssignedToSubrequest()
     {
         $expectedSubRequest = Request::create('/');
-        if (Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP)) {
-            $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
-            $expectedSubRequest->server->set('HTTP_X_FORWARDED_FOR', '127.0.0.1');
-        }
+        $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
+        $expectedSubRequest->headers->set('forwarded', array('for="127.0.0.1";host="localhost";proto=http'));
 
         $strategy = new InlineFragmentRenderer($this->getKernelExpectingRequest($expectedSubRequest));
         $request = Request::create('/', 'GET', array(), array(), array(), array('HTTP_IF_MODIFIED_SINCE' => 'Fri, 01 Jan 2016 00:00:00 GMT', 'HTTP_IF_NONE_MATCH' => '*'));
@@ -208,12 +213,9 @@
     {
         $expectedSubRequest = Request::create('/');
         $expectedSubRequest->headers->set('Surrogate-Capability', 'abc="ESI/1.0"');
-        $expectedSubRequest->server->set('REMOTE_ADDR', '1.1.1.1');
-
-        if (Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP)) {
-            $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
-            $expectedSubRequest->server->set('HTTP_X_FORWARDED_FOR', '127.0.0.1');
-        }
+        $expectedSubRequest->server->set('REMOTE_ADDR', '127.0.0.1');
+        $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
+        $expectedSubRequest->headers->set('forwarded', array('for="127.0.0.1";host="localhost";proto=http'));
 
         Request::setTrustedProxies(array('1.1.1.1'));
 
@@ -230,9 +232,9 @@
     {
         $expectedSubRequest = Request::create('/');
         $expectedSubRequest->headers->set('Surrogate-Capability', 'abc="ESI/1.0"');
-        $expectedSubRequest->server->set('REMOTE_ADDR', '1.1.1.1');
-        $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
-        $expectedSubRequest->server->set('HTTP_X_FORWARDED_FOR', '127.0.0.1');
+        $expectedSubRequest->server->set('REMOTE_ADDR', '127.0.0.1');
+        $expectedSubRequest->headers->set('x-forwarded-for', array('127.0.0.1'));
+        $expectedSubRequest->headers->set('forwarded', array('for="127.0.0.1";host="localhost";proto=http'));
 
         Request::setTrustedProxies(array('1.1.1.1/24'));
 
```
