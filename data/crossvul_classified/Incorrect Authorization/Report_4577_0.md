# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4577_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4577_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

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

namespace PrestaShopBundle\Controller\Admin;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin controller for product attachments (in /product/form page).
 */
class AttachementProductController extends FrameworkBundleAdminController
{
    /**
     * Manage form add product attachment.
     *
     * @param int $idProduct
     * @param Request $request
     *
     * @return string
     */
    public function addAction($idProduct, Request $request)
    {
        $response = new JsonResponse();
        $legacyContext = $this->get('prestashop.adapter.legacy.context');
        $adminProductWrapper = $this->get('prestashop.adapter.admin.wrapper.product');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
 
 namespace PrestaShopBundle\Controller\Admin;
 
+use PrestaShopBundle\Security\Annotation\AdminSecurity;
 use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\Request;
 
@@ -37,10 +38,12 @@
     /**
      * Manage form add product attachment.
      *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     *
      * @param int $idProduct
      * @param Request $request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function addAction($idProduct, Request $request)
     {
```
