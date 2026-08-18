# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4076_7
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4076_7`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

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

namespace PrestaShopBundle\Controller\Admin\Improve;

use DateTime;
use Exception;
use Module;
use PrestaShop\PrestaShop\Adapter\Module\AdminModuleDataProvider;
use PrestaShop\PrestaShop\Core\Addon\AddonListFilter;
use PrestaShop\PrestaShop\Core\Addon\AddonListFilterStatus;
use PrestaShop\PrestaShop\Core\Addon\AddonListFilterType;
use PrestaShop\PrestaShop\Core\Addon\AddonsCollection;
use PrestaShop\PrestaShop\Core\Addon\Module\Exception\UnconfirmedModuleActionException;
use PrestaShop\PrestaShop\Core\Addon\Module\ModuleRepository;
use PrestaShopBundle\Controller\Admin\Improve\Modules\ModuleAbstractController;
use PrestaShopBundle\Entity\ModuleHistory;
use PrestaShopBundle\Security\Annotation\AdminSecurity;
use PrestaShopBundle\Security\Voter\PageVoter;
use PrestaShopBundle\Service\DataProvider\Admin\CategoriesProvider;
use Profile;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Responsible of "Improve > Modules > Modules & Services > Catalog / Manage" page display.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 use Exception;
 use Module;
 use PrestaShop\PrestaShop\Adapter\Module\AdminModuleDataProvider;
+use PrestaShop\PrestaShop\Adapter\Module\Module as ModuleAdapter;
 use PrestaShop\PrestaShop\Core\Addon\AddonListFilter;
 use PrestaShop\PrestaShop\Core\Addon\AddonListFilterStatus;
 use PrestaShop\PrestaShop\Core\Addon\AddonListFilterType;
@@ -58,7 +59,7 @@
     const MAX_MODULES_DISPLAYED = 6;
 
     /**
-     * @AdminSecurity("is_granted(['read', 'create', 'update', 'delete'], 'ADMINMODULESSF_')")
+     * @AdminSecurity("is_granted(['read'], 'ADMINMODULESSF_')")
      *
      * @return Response
      */
@@ -87,7 +88,7 @@
     /**
      * Controller responsible for displaying "Catalog Module Grid" section of Module management pages with ajax.
      *
-     * @AdminSecurity("is_granted(['read', 'create', 'update', 'delete'], 'ADMINMODULESSF_')")
+     * @AdminSecurity("is_granted(['read'], 'ADMINMODULESSF_')")
      *
      * @param Request $request
      *
@@ -146,7 +147,7 @@
     }
 
     /**
-     * @AdminSecurity("is_granted(['read', 'create', 'update', 'delete'], 'ADMINMODULESSF_')")
+     * @AdminSecurity("is_granted(['read'], 'ADMINMODULESSF_')")
      *
      * @param Request $request
      *
@@ -263,7 +264,7 @@
     }
 
     /**
-     * @AdminSecurity("is_granted(['read', 'create', 'update', 'delete'], 'ADMINMODULESSF_')")
+     * @AdminSecurity("is_granted(['read'], 'ADMINMODULESSF_')")
      *
      * @param Request $request
      *
@@ -353,14 +354,37 @@
      */
     public function moduleAction(Request $request)
     {
-        $deniedAccess = $this->checkPermissions(
-            [
-                PageVoter::LEVEL_READ,
-                PageVoter::LEVEL_UPDATE,
-                PageVoter::LEVEL_CREATE,
-                PageVoter::LEVEL_DELETE,
-            ]
-        );
+        $action = $request->get('action');
+
+        switch ($action) {
+            case ModuleAdapter::ACTION_UPGRADE:
+            case ModuleAdapter::ACTION_RESET:
+            case ModuleAdapter::ACTION_ENABLE:
+            case ModuleAdapter::ACTION_DISABLE:
+            case ModuleAdapter::ACTION_ENABLE_MOBILE:
+            case ModuleAdapter::ACTION_DISABLE_MOBILE:
+                $deniedAccess = $this->checkPermissions(
+                    [
+                        PageVoter::LEVEL_UPDATE,
+                    ]
+                );
+                break;
+            case ModuleAdapter::ACTION_INSTALL:
+                $deniedAccess = $this->checkPermissions(
+                    [
+                        PageVoter::LEVEL_CREATE,
+                    ]
+                );
+                break;
+            case ModuleAdapter::ACTION_UNINSTALL:
+                $deniedAccess = $this->checkPermissions(
+                    [
+                        PageVoter::LEVEL_DELETE,
+                    ]
+                );
+                break;
+        }
+
         if (null !== $deniedAccess) {
             return $deniedAccess;
         }
@@ -369,7 +393,6 @@
             return $this->getDisabledFunctionalityResponse($request);
         }
 
-        $action = $request->get('action');
         $module = $request->get('module_name');
         $moduleManager = $this->container->get('prestashop.module.manager');
         $moduleManager->setActionParams($request->request->get('actionParams', []));
```
