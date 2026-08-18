# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4565_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4565_0`)

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
 * needs please refer to https://www.prestashop.com for more information.
 *
 * @author    PrestaShop SA <contact@prestashop.com>
 * @copyright 2007-2019 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 * International Registered Trademark & Property of PrestaShop SA
 */

namespace PrestaShopBundle\EventListener;

use PrestaShop\PrestaShop\Core\Util\Url\BackUrlProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

/**
 * This class allows to redirect to back url.
 */
final class BackUrlRedirectResponseListener
{
    /**
     * @var BackUrlProvider
     */
    private $backUrlProvider;

    /**
     * @param BackUrlProvider $backUrlProvider
     */
    public function __construct(
        BackUrlProvider $backUrlProvider
    ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,8 @@
 
 namespace PrestaShopBundle\EventListener;
 
+use Employee;
+use PrestaShop\PrestaShop\Adapter\LegacyContext;
 use PrestaShop\PrestaShop\Core\Util\Url\BackUrlProvider;
 use Symfony\Component\HttpFoundation\RedirectResponse;
 use Symfony\Component\HttpFoundation\Request;
@@ -42,16 +44,31 @@
     private $backUrlProvider;
 
     /**
+     * @var int
+     */
+    private $employeeId;
+
+    /**
      * @param BackUrlProvider $backUrlProvider
      */
     public function __construct(
-        BackUrlProvider $backUrlProvider
-    ) {
+        BackUrlProvider $backUrlProvider,
+        LegacyContext $legacyContext
+   ) {
         $this->backUrlProvider = $backUrlProvider;
+        $context = $legacyContext->getContext();
+        if (null !== $context && $context->employee instanceof Employee) {
+            $this->employeeId = $context->employee->id;
+        }
     }
 
     public function onKernelResponse(FilterResponseEvent $event)
     {
+        // No need to continue because the employee is not connected
+        if (empty($this->employeeId)) {
+            return;
+        }
+
         $currentRequest = $event->getRequest();
         $originalResponse = $event->getResponse();
 
```
