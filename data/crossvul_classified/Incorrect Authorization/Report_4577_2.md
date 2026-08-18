# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4577_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4577_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

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

use DateTime;
use Exception;
use PrestaShop\PrestaShop\Adapter\Product\AdminProductWrapper;
use PrestaShop\PrestaShop\Core\Foundation\Database\EntityDataInconsistencyException;
use PrestaShop\PrestaShop\Core\Foundation\Database\EntityNotFoundException;
use PrestaShopBundle\Form\Admin\Product\ProductSpecificPrice as SpecificPriceFormType;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Admin controller for the attribute / attribute group.
 */
class SpecificPriceController extends FrameworkBundleAdminController
{
    /**
     * get specific price list for a product.
     *
     * @param $idProduct The product ID
     *
     * @return string JSON
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,10 +28,11 @@
 
 use DateTime;
 use Exception;
+use PrestaShopBundle\Form\Admin\Product\ProductSpecificPrice as SpecificPriceFormType;
+use PrestaShopBundle\Security\Annotation\AdminSecurity;
 use PrestaShop\PrestaShop\Adapter\Product\AdminProductWrapper;
 use PrestaShop\PrestaShop\Core\Foundation\Database\EntityDataInconsistencyException;
 use PrestaShop\PrestaShop\Core\Foundation\Database\EntityNotFoundException;
-use PrestaShopBundle\Form\Admin\Product\ProductSpecificPrice as SpecificPriceFormType;
 use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
 use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\Request;
@@ -43,11 +44,13 @@
 class SpecificPriceController extends FrameworkBundleAdminController
 {
     /**
-     * get specific price list for a product.
+     * Get specific price list for a product.
+     *
+     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
      *
      * @param $idProduct The product ID
      *
-     * @return string JSON
+     * @return JsonResponse
      */
     public function listAction($idProduct)
     {
@@ -86,9 +89,11 @@
     /**
      * Add specific price Form process.
      *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     *
      * @param Request $request The request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function addAction(Request $request)
     {
@@ -110,6 +115,8 @@
      * Get one specific price list for a product.
      *
      * @Template("@PrestaShop/Admin/Product/ProductPage/Forms/form_specific_price.html.twig")
+     *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
      *
      * @param int $idSpecificPrice
      *
@@ -157,10 +164,12 @@
     /**
      * Update specific price Form process.
      *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     *
      * @param int idSpecificPrice
      * @param Request $request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function updateAction($idSpecificPrice, Request $request)
     {
@@ -185,10 +194,12 @@
     /**
      * Delete a specific price.
      *
+     * @AdminSecurity("is_granted(['delete'], 'ADMINPRODUCTS_')")
+     *
      * @param int $idSpecificPrice The specific price ID
      * @param Request $request The request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function deleteAction($idSpecificPrice, Request $request)
     {
@@ -253,7 +264,7 @@
     /**
      * @param string $dateAsString
      *
-     * @return string|null If date is 0000-00-00 00:00:00, null is returned
+     * @return JsonResponse|null If date is 0000-00-00 00:00:00, null is returned
      *
      * @throws \PrestaShopDatabaseExceptionCore if date is not valid
      */
```
