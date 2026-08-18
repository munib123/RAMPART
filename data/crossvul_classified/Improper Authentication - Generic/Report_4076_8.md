# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4076_8
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4076_8`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

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

namespace PrestaShopBundle\Controller\Api\Improve\Design;

use PrestaShopBundle\Controller\Api\ApiController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class PositionsController extends ApiController
{
    /**
     * Update positions.
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function updateAction(Request $request)
    {
        $moduleId = $request->request->getInt('moduleId');
        $hookId = $request->request->getInt('hookId');
        $way = $request->request->getInt('way');
        $positions = $request->request->get('positions');
        $position = (int) is_array($positions) ? array_search($hookId . '_' . $moduleId, $positions) + 1 : null;

        $module = $this->container->get('prestashop.adapter.legacy.module')->getInstanceById($moduleId);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 namespace PrestaShopBundle\Controller\Api\Improve\Design;
 
 use PrestaShopBundle\Controller\Api\ApiController;
+use PrestaShopBundle\Security\Annotation\AdminSecurity;
 use Symfony\Component\HttpFoundation\JsonResponse;
 use Symfony\Component\HttpFoundation\Request;
 
@@ -34,6 +35,8 @@
 {
     /**
      * Update positions.
+     *
+     * @AdminSecurity("is_granted(['update'], request.get('_legacy_controller'))")
      *
      * @param Request $request
      *
```
