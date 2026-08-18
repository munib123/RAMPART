# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4576_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4576_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 10-50 of the vulnerable file.

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

use Product;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Admin controller for the attribute / attribute group.
 */
class AttributeController extends FrameworkBundleAdminController
{
    /**
     * get All Attributes as json.
     *
     * @return string
     */
    public function getAllAttributesAction()
    {
        $response = new JsonResponse();
        $locales = $this->get('prestashop.adapter.legacy.context')->getLanguages();
        $attributes = $this->get('prestashop.adapter.data_provider.attribute')->getAttributes($locales[0]['id_lang'], true);

        $dataGroupAttributes = [];
        $data = [];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 namespace PrestaShopBundle\Controller\Admin;
 
 use Product;
+use PrestaShopBundle\Security\Annotation\AdminSecurity;
 use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\Request;
 
@@ -38,7 +39,9 @@
     /**
      * get All Attributes as json.
      *
-     * @return string
+     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
+     *
+     * @return JsonResponse
      */
     public function getAllAttributesAction()
     {
@@ -79,9 +82,11 @@
     /**
      * Attributes generator.
      *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     *
      * @param Request $request The request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function attributesGeneratorAction(Request $request)
     {
@@ -195,10 +200,12 @@
     /**
      * Delete a product attribute.
      *
+     * @AdminSecurity("is_granted(['delete'], 'ADMINPRODUCTS_')")
+     *
      * @param int $idProduct The product ID
      * @param Request $request The request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function deleteAttributeAction($idProduct, Request $request)
     {
@@ -230,10 +237,12 @@
     /**
      * Delete all product attributes.
      *
+     * @AdminSecurity("is_granted(['delete'], 'ADMINPRODUCTS_')")
+     *
      * @param int $idProduct The product ID
      * @param Request $request The request
      *
-     * @return string
+     * @return JsonResponse
      */
     public function deleteAllAttributeAction($idProduct, Request $request)
     {
@@ -268,10 +277,12 @@
     /**
      * get the images form for a product combinations.
      *
+     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
+     *
      * @param int $idProduct The product id
      * @param Request $request The request
      *
-     * @return string Json
+     * @return JsonResponse
      */
     public function getFormImagesAction($idProduct, Request $request)
     {
```
