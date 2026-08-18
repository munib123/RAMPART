# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4560_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4560_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

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

namespace PrestaShopBundle\Controller\Admin;

use PrestaShopBundle\Service\Routing\Router as PrestaShopRouter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin controller to manage security pages.
 */
class SecurityController extends FrameworkBundleAdminController
{
    public function compromisedAccessAction(Request $request)
    {
        $requestUri = urldecode($request->query->get('uri'));

        // getToken() actually generate a new token
        $username = $this->get('prestashop.user_provider')->getUsername();

        $newToken = $this->get('security.csrf.token_manager')
            ->getToken($username)
            ->getValue();

        $newUri = PrestaShopRouter::generateTokenizedUrl($requestUri, $newToken);

        return $this->render('@PrestaShop/Admin/Security/compromised.html.twig', array(
            'requestUri' => $newUri,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
 
 use PrestaShopBundle\Service\Routing\Router as PrestaShopRouter;
 use Symfony\Component\HttpFoundation\Request;
+use Symfony\Component\Validator\Constraints as Assert;
 
 /**
  * Admin controller to manage security pages.
@@ -37,6 +38,11 @@
     public function compromisedAccessAction(Request $request)
     {
         $requestUri = urldecode($request->query->get('uri'));
+        $url = new Assert\Url();
+        $violations = $this->get('validator')->validate($requestUri, [$url]);
+        if ($violations->count()) {
+            return $this->redirect('dashboard');
+        }
 
         // getToken() actually generate a new token
         $username = $this->get('prestashop.user_provider')->getUsername();
@@ -47,8 +53,11 @@
 
         $newUri = PrestaShopRouter::generateTokenizedUrl($requestUri, $newToken);
 
-        return $this->render('@PrestaShop/Admin/Security/compromised.html.twig', array(
-            'requestUri' => $newUri,
-        ));
+        return $this->render(
+            '@PrestaShop/Admin/Security/compromised.html.twig',
+            array(
+                'requestUri' => $newUri,
+            )
+        );
     }
 }
```
