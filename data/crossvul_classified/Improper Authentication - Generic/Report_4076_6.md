# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4076_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4076_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

 * @copyright 2007-2019 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 * International Registered Trademark & Property of PrestaShop SA
 */

namespace PrestaShop\PrestaShop\Adapter\Module;

use Module as LegacyModule;
use PrestaShop\PrestaShop\Core\Addon\AddonListFilterOrigin;
use PrestaShop\PrestaShop\Core\Addon\Module\AddonListFilterDeviceStatus;
use PrestaShop\PrestaShop\Core\Addon\Module\ModuleInterface;
use Symfony\Component\HttpFoundation\ParameterBag;

/**
 * This class is the interface to the legacy Module class.
 *
 * It will allow current modules to work even with the new ModuleManager
 */
class Module implements ModuleInterface
{
    /** @var LegacyModule Module The instance of the legacy module */
    public $instance = null;

    /**
     * Module attributes (name, displayName etc.).
     *
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    public $attributes;

    /**
     * Module attributes from disk.
     *
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    public $disk;

    /**
     * Module attributes from database.
     *
     * @var \Symfony\Component\HttpFoundation\ParameterBag
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,15 @@
  */
 class Module implements ModuleInterface
 {
+    const ACTION_INSTALL = 'install';
+    const ACTION_UNINSTALL = 'uninstall';
+    const ACTION_ENABLE = 'enable';
+    const ACTION_DISABLE = 'disable';
+    const ACTION_ENABLE_MOBILE = 'enable_mobile';
+    const ACTION_DISABLE_MOBILE = 'disable_mobile';
+    const ACTION_RESET = 'reset';
+    const ACTION_UPGRADE = 'upgrade';
+
     /** @var LegacyModule Module The instance of the legacy module */
     public $instance = null;
 
```
