# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 284_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `284_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel\Fragment;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Controller\ControllerReference;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Implements the inline rendering strategy where the Request is rendered by the current HTTP kernel.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class InlineFragmentRenderer extends RoutableFragmentRenderer
{
    private $kernel;
    private $dispatcher;

    public function __construct(HttpKernelInterface $kernel, EventDispatcherInterface $dispatcher = null)
    {
        $this->kernel = $kernel;
        $this->dispatcher = $dispatcher;
    }

    /**
     * {@inheritdoc}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 use Symfony\Component\HttpFoundation\Response;
 use Symfony\Component\HttpKernel\Controller\ControllerReference;
 use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
+use Symfony\Component\HttpKernel\HttpCache\SubRequestHandler;
 use Symfony\Component\HttpKernel\HttpKernelInterface;
 use Symfony\Component\HttpKernel\KernelEvents;
 
@@ -76,7 +77,7 @@
 
         $level = ob_get_level();
         try {
-            return $this->kernel->handle($subRequest, HttpKernelInterface::SUB_REQUEST, false);
+            return SubRequestHandler::handle($this->kernel, $subRequest, HttpKernelInterface::SUB_REQUEST, false);
         } catch (\Exception $e) {
             // we dispatch the exception event to trigger the logging
             // the response that comes back is simply ignored
@@ -109,21 +110,6 @@
         $cookies = $request->cookies->all();
         $server = $request->server->all();
 
-        // Override the arguments to emulate a sub-request.
-        // Sub-request object will point to localhost as client ip and real client ip
-        // will be included into trusted header for client ip
-        try {
-            if ($trustedHeaderName = Request::getTrustedHeaderName(Request::HEADER_CLIENT_IP)) {
-                $currentXForwardedFor = $request->headers->get($trustedHeaderName, '');
-
-                $server['HTTP_'.$trustedHeaderName] = ($currentXForwardedFor ? $currentXForwardedFor.', ' : '').$request->getClientIp();
-            }
-        } catch (\InvalidArgumentException $e) {
-            // Do nothing
-        }
-
-        $server['REMOTE_ADDR'] = $this->resolveTrustedProxy();
-
         unset($server['HTTP_IF_MODIFIED_SINCE']);
         unset($server['HTTP_IF_NONE_MATCH']);
 
@@ -139,17 +125,6 @@
         return $subRequest;
     }
 
-    private function resolveTrustedProxy()
-    {
-        if (!$trustedProxies = Request::getTrustedProxies()) {
-            return '127.0.0.1';
-        }
-
-        $firstTrustedProxy = reset($trustedProxies);
-
-        return false !== ($i = strpos($firstTrustedProxy, '/')) ? substr($firstTrustedProxy, 0, $i) : $firstTrustedProxy;
-    }
-
     /**
      * {@inheritdoc}
      */
```
