# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4577_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4577_1`)

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

use PrestaShopBundle\Form\Admin\Product\ProductCombination;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

class CombinationController extends FrameworkBundleAdminController
{
    public function generateCombinationFormAction($combinationIds)
    {
        $response = new Response();

        $combinationIds = explode('-', $combinationIds);
        if ($combinationIds === false || count($combinationIds) == 0) {
            return $response;
        }

        $combinationDataProvider = $this->get('prestashop.adapter.data_provider.combination');
        $combinations = $combinationDataProvider->getFormCombinations($combinationIds, (int) $this->getContext()->language->id);

        $formFactory = $this->get('form.factory');
        foreach ($combinations as $combinationId => $combination) {
            $forms[] = $formFactory->createNamed(
                "combination_$combinationId",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,11 +27,19 @@
 namespace PrestaShopBundle\Controller\Admin;
 
 use PrestaShopBundle\Form\Admin\Product\ProductCombination;
+use PrestaShopBundle\Security\Annotation\AdminSecurity;
 use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\Response;
 
 class CombinationController extends FrameworkBundleAdminController
 {
+    /**
+     * Generate combination
+     *
+     * @AdminSecurity("is_granted(['create', 'update'], 'ADMINPRODUCTS_')")
+     *
+     * @return Response
+     */
     public function generateCombinationFormAction($combinationIds)
     {
         $response = new Response();
@@ -62,11 +70,13 @@
     }
 
     /**
-     * get All Combinations for a product.
+     * Get all Combinations for a product.
+     *
+     * @AdminSecurity("is_granted(['read'], 'ADMINPRODUCTS_')")
      *
      * @param int $idProduct The product id
      *
-     * @return string Json
+     * @return JsonResponse
      */
     public function getProductCombinationsAction($idProduct)
     {
```
