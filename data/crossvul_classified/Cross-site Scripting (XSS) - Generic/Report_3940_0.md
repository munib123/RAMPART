# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3940_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3940_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php namespace Backend;

use App;
use Backend;
use BackendMenu;
use BackendAuth;
use Backend\Classes\WidgetManager;
use System\Classes\MailManager;
use System\Classes\CombineAssets;
use System\Classes\SettingsManager;
use October\Rain\Support\ModuleServiceProvider;

class ServiceProvider extends ModuleServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        parent::register('backend');

        $this->registerMailer();
        $this->registerAssetBundles();

        /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 use Backend;
 use BackendMenu;
 use BackendAuth;
+use Backend\Models\UserRole;
 use Backend\Classes\WidgetManager;
 use System\Classes\MailManager;
 use System\Classes\CombineAssets;
@@ -168,7 +169,12 @@
                 'media.manage_media' => [
                     'label' => 'backend::lang.permissions.manage_media',
                     'tab' => 'system::lang.permissions.name',
-                ]
+                ],
+                'backend.allow_unsafe_markdown' => [
+                    'label' => 'backend::lang.permissions.allow_unsafe_markdown',
+                    'tab' => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
+                ],
             ]);
         });
     }
```
