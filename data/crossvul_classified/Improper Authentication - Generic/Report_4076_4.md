# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4076_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4076_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 519-562 of the vulnerable file.

            $_POST['token'] = $this->token;
        }

        if (!Shop::isFeatureActive()) {
            $this->shopLinkType = '';
        }

        //$this->base_template_folder = _PS_BO_ALL_THEMES_DIR_.$this->bo_theme.'/template';
        $this->override_folder = Tools::toUnderscoreCase(substr($this->controller_name, 5)) . '/';
        // Get the name of the folder containing the custom tpl files
        $this->tpl_folder = Tools::toUnderscoreCase(substr($this->controller_name, 5)) . '/';

        $this->initShopContext();

        if (defined('_PS_ADMIN_DIR_')) {
            $this->admin_webpath = str_ireplace(_PS_CORE_DIR_, '', _PS_ADMIN_DIR_);
            $this->admin_webpath = preg_replace('/^' . preg_quote(DIRECTORY_SEPARATOR, '/') . '/', '', $this->admin_webpath);
        }

        // Check if logged on Addons
        $this->logged_on_addons = false;
        if (isset($this->context->cookie->username_addons, $this->context->cookie->password_addons) && !empty($this->context->cookie->username_addons) && !empty($this->context->cookie->password_addons)) {
            $this->logged_on_addons = true;
        }

        // Set context mode
        if (defined('_PS_HOST_MODE_') && _PS_HOST_MODE_) {
            if (isset($this->context->cookie->is_contributor) && (int) $this->context->cookie->is_contributor === 1) {
                $this->context->mode = Context::MODE_HOST_CONTRIB;
            } else {
                $this->context->mode = Context::MODE_HOST;
            }
        } elseif (isset($this->context->cookie->is_contributor) && (int) $this->context->cookie->is_contributor === 1) {
            $this->context->mode = Context::MODE_STD_CONTRIB;
        } else {
            $this->context->mode = Context::MODE_STD;
        }

        //* Check if logged employee has access to AdminImport controller */
        $import_access = Profile::getProfileAccess($this->context->employee->id_profile, Tab::getIdFromClassName('AdminImport'));
        if (is_array($import_access) && isset($import_access['view']) && $import_access['view'] == 1) {
            $this->can_import = true;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -536,10 +536,7 @@
         }
 
         // Check if logged on Addons
-        $this->logged_on_addons = false;
-        if (isset($this->context->cookie->username_addons, $this->context->cookie->password_addons) && !empty($this->context->cookie->username_addons) && !empty($this->context->cookie->password_addons)) {
-            $this->logged_on_addons = true;
-        }
+        $this->logged_on_addons = !empty($this->context->cookie->username_addons) && !empty($this->context->cookie->password_addons);
 
         // Set context mode
         if (defined('_PS_HOST_MODE_') && _PS_HOST_MODE_) {
```
