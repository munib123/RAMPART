# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4565_2
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4565_2`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/OSL-3.0
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade PrestaShop to newer
 * versions in the future. If you wish to customize PrestaShop for your
 * needs please refer to http://www.prestashop.com for more information.
 *
 * @author    PrestaShop SA <contact@prestashop.com>
 * @copyright 2007-2019 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 * International Registered Trademark & Property of PrestaShop SA
 */

namespace Tests\Unit\PrestaShopBundle\EventListener;

use PHPUnit\Framework\TestCase;
use PrestaShop\PrestaShop\Core\Util\Url\BackUrlProvider;
use PrestaShopBundle\EventListener\BackUrlRedirectResponseListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class BackUrlRedirectResponseListenerTest extends TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject|FilterResponseEvent
     */
    private $filterResponseEventMock;

    protected function setUp()
    {
        parent::setUp();

        $this->filterResponseEventMock = $this
            ->getMockBuilder(FilterResponseEvent::class)
            ->disableOriginalConstructor()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,10 @@
 
 namespace Tests\Unit\PrestaShopBundle\EventListener;
 
+use Employee;
+use Context;
 use PHPUnit\Framework\TestCase;
+use PrestaShop\PrestaShop\Adapter\LegacyContext;
 use PrestaShop\PrestaShop\Core\Util\Url\BackUrlProvider;
 use PrestaShopBundle\EventListener\BackUrlRedirectResponseListener;
 use Symfony\Component\HttpFoundation\RedirectResponse;
@@ -51,19 +54,47 @@
         ;
     }
 
+    protected function getLegacyContextMock($isConnected = true)
+    {
+        $legacyContextMock = $this->getMockBuilder(LegacyContext::class)
+            ->setMethods(array(
+                'getContext',
+            ))
+            ->getMock();
+
+        $employeeMock = $this->getMockBuilder(Employee::class)->getMock();
+        $employeeMock->id = $isConnected ? 1 : null;
+
+        $contextMock = $this->getMockBuilder(Context::class)->getMock();
+        $contextMock->employee = $employeeMock;
+
+        $legacyContextMock->expects($this->any())->method('getContext')->willReturn($contextMock);
+
+        return $legacyContextMock;
+    }
+
+    protected function getBackUrlProviderMock($backUrl)
+    {
+        $backUrlProviderMock = $this
+            ->getMockBuilder(BackUrlProvider::class)
+            ->getMock()
+        ;
+
+        $backUrlProviderMock
+            ->method('getBackUrl')
+            ->willReturn($backUrl)
+        ;
+        return $backUrlProviderMock;
+    }
+
     public function testItSetsResponseWithBackUrl()
     {
         $expectedUrl = 'http://localhost';
 
-        $backUrlProvider = $this
-            ->getMockBuilder(BackUrlProvider::class)
-            ->getMock()
-        ;
-
-        $backUrlProvider
-            ->method('getBackUrl')
-            ->willReturn($expectedUrl)
-        ;
+        $legacyContextMock = $this->getLegacyContextMock();
+        $backUrlProviderMock = $this->getBackUrlProviderMock(
+            $expectedUrl
+        );
 
         $this->filterResponseEventMock
             ->method('getResponse')
@@ -75,7 +106,10 @@
             ->willReturn(new Request())
         ;
 
-        $responseListener = new BackUrlRedirectResponseListener($backUrlProvider);
+        $responseListener = new BackUrlRedirectResponseListener(
+            $backUrlProviderMock,
+            $legacyContextMock
+        );
 
         $responseListener->onKernelResponse($this->filterResponseEventMock);
 
@@ -87,19 +121,14 @@
 
     public function testWhenRequestAndResponseUrlsAreEqualItDoesNotModifyOriginalResponse()
     {
-        $requestAndResponseUrl = 'http://localhost';
+        $expectedUrl = 'http://localhost';
 
-        $backUrlProvider = $this
-            ->getMockBuilder(BackUrlProvider::class)
-            ->getMock()
-        ;
+        $legacyContextMock = $this->getLegacyContextMock();
+        $backUrlProviderMock = $this->getBackUrlProviderMock(
+            'http://localhost-not-called.dev'
+        );
 
-        $backUrlProvider
-            ->method('getBackUrl')
-            ->willReturn('http://localhost-not-called.dev')
-        ;
-
-        $originalRedirectResponse = new RedirectResponse($requestAndResponseUrl);
+        $originalRedirectResponse = new RedirectResponse($expectedUrl);
 
         $this->filterResponseEventMock
             ->method('getResponse')
@@ -112,7 +141,7 @@
 
         $currentRequest
             ->method('getRequestUri')
-            ->willReturn($requestAndResponseUrl)
+            ->willReturn($expectedUrl)
         ;
 
         $this->filterResponseEventMock
@@ -120,7 +149,10 @@
             ->willReturn($currentRequest)
         ;
 
-        $responseListener = new BackUrlRedirectResponseListener($backUrlProvider);
+        $responseListener = new BackUrlRedirectResponseListener(
+            $backUrlProviderMock,
+            $legacyContextMock
+        );
 
         $responseListener->onKernelResponse($this->filterResponseEventMock);
 
@@ -128,4 +160,21 @@
 
         $this->assertEquals($originalRedirectResponse, $actual);
     }
+
+    public function testWhenEmployeeIsNotConnected()
+    {
+        $expectedUrl = 'http://localhost';
+
+        $legacyContextMock = $this->getLegacyContextMock(false);
+        $backUrlProviderMock = $this->getBackUrlProviderMock(
+            'http://localhost-not-called.dev'
+        );
+
+        $responseListener = new BackUrlRedirectResponseListener(
+            $backUrlProviderMock,
+            $legacyContextMock
+        );
+
+        $this->assertNull($responseListener->onKernelResponse($this->filterResponseEventMock));
+    }
 }
```
