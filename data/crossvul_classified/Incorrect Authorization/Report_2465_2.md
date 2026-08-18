# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 2465_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2465_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

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

namespace Symfony\Component\Security\Http\Tests\Firewall;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Http\AccessMapInterface;
use Symfony\Component\Security\Http\Event\LazyResponseEvent;
use Symfony\Component\Security\Http\Firewall\AccessListener;

class AccessListenerTest extends TestCase
{
    public function testHandleWhenTheAccessDecisionManagerDecidesToRefuseAccess()
    {
        $this->expectException('Symfony\Component\Security\Core\Exception\AccessDeniedException');
        $request = new Request();

        $accessMap = $this->getMockBuilder('Symfony\Component\Security\Http\AccessMapInterface')->getMock();
        $accessMap
            ->expects($this->any())
            ->method('getPatterns')
            ->with($this->equalTo($request))
            ->willReturn([['foo' => 'bar'], null])
        ;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 use Symfony\Component\HttpKernel\Event\RequestEvent;
 use Symfony\Component\HttpKernel\HttpKernelInterface;
 use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
+use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
 use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
 use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
 use Symfony\Component\Security\Http\AccessMapInterface;
@@ -227,4 +228,44 @@
 
         $listener(new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MASTER_REQUEST));
     }
+
+    public function testHandleMWithultipleAttributesShouldBeHandledAsAnd()
+    {
+        $request = new Request();
+
+        $accessMap = $this->getMockBuilder('Symfony\Component\Security\Http\AccessMapInterface')->getMock();
+        $accessMap
+            ->expects($this->any())
+            ->method('getPatterns')
+            ->with($this->equalTo($request))
+            ->willReturn([['foo' => 'bar', 'bar' => 'baz'], null])
+        ;
+
+        $authenticatedToken = $this->getMockBuilder('Symfony\Component\Security\Core\Authentication\Token\TokenInterface')->getMock();
+        $authenticatedToken
+            ->expects($this->any())
+            ->method('isAuthenticated')
+            ->willReturn(true)
+        ;
+
+        $tokenStorage = new TokenStorage();
+        $tokenStorage->setToken($authenticatedToken);
+
+        $accessDecisionManager = $this->getMockBuilder('Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface')->getMock();
+        $accessDecisionManager
+            ->expects($this->once())
+            ->method('decide')
+            ->with($this->equalTo($authenticatedToken), $this->equalTo(['foo' => 'bar', 'bar' => 'baz']), $this->equalTo($request), true)
+            ->willReturn(true)
+        ;
+
+        $listener = new AccessListener(
+            $tokenStorage,
+            $accessDecisionManager,
+            $accessMap,
+            $this->createMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface')
+        );
+
+        $listener(new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MASTER_REQUEST));
+    }
 }
```
