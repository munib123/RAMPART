# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

 * @copyright 2007-2019 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 * International Registered Trademark & Property of PrestaShop SA
 */

namespace PrestaShopBundle\Controller\Admin;

use Product;
use PrestaShopBundle\Security\Annotation\AdminSecurity;
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
     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
     *
     * @return JsonResponse
     */
    public function getAllAttributesAction()
    {
        $response = new JsonResponse();
        $locales = $this->get('prestashop.adapter.legacy.context')->getLanguages();
        $attributes = $this->get('prestashop.adapter.data_provider.attribute')->getAttributes($locales[0]['id_lang'], true);

        $dataGroupAttributes = [];
        $data = [];
        foreach ($attributes as $attribute) {
            /* Construct attribute group selector. Ex : Color : All */
            $dataGroupAttributes[$attribute['id_attribute_group']] = [
                'value' => 'group-' . $attribute['id_attribute_group'],
                'label' => $attribute['public_name'] . ' : ' . $this->trans('All', 'Admin.Global'),
                'data' => [
                    'id_group' => $attribute['id_attribute_group'],
                    'name' => $attribute['public_name'],
                ],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
     /**
      * get All Attributes as json.
      *
-     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
+     * @AdminSecurity("is_granted(['read'], request.get('_legacy_controller'))")
      *
      * @return JsonResponse
      */
@@ -82,7 +82,7 @@
     /**
      * Attributes generator.
      *
-     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     * @AdminSecurity("is_granted(['create', 'update'], request.get('_legacy_controller'))")
      *
      * @param Request $request The request
      *
@@ -200,7 +200,7 @@
     /**
      * Delete a product attribute.
      *
-     * @AdminSecurity("is_granted(['delete'], 'ADMINPRODUCTS_')")
+     * @AdminSecurity("is_granted(['delete'], request.get('_legacy_controller'))")
      *
      * @param int $idProduct The product ID
      * @param Request $request The request
@@ -237,7 +237,7 @@
     /**
      * Delete all product attributes.
      *
-     * @AdminSecurity("is_granted(['delete'], 'ADMINPRODUCTS_')")
+     * @AdminSecurity("is_granted(['delete'], request.get('_legacy_controller'))")
      *
      * @param int $idProduct The product ID
      * @param Request $request The request
@@ -277,7 +277,7 @@
     /**
      * get the images form for a product combinations.
      *
-     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
+     * @AdminSecurity("is_granted(['read'], request.get('_legacy_controller'))")
      *
      * @param int $idProduct The product id
      * @param Request $request The request
```
