# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4187_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4187_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php namespace System;

use Db;
use App;
use View;
use Event;
use Config;
use Backend;
use Request;
use BackendMenu;
use BackendAuth;
use Twig\Extension\SandboxExtension;
use Twig\Environment as TwigEnvironment;
use System\Classes\MailManager;
use System\Classes\ErrorHandler;
use System\Classes\MarkupManager;
use System\Classes\PluginManager;
use System\Classes\SettingsManager;
use System\Classes\UpdateManager;
use System\Twig\Engine as TwigEngine;
use System\Twig\Loader as TwigLoader;
use System\Twig\Extension as TwigExtension;
use System\Twig\SecurityPolicy as TwigSecurityPolicy;
use System\Models\EventLog;
use System\Models\MailSetting;
use System\Classes\CombineAssets;
use Backend\Classes\WidgetManager;
use October\Rain\Support\ModuleServiceProvider;
use October\Rain\Router\Helper as RouterHelper;
use Illuminate\Pagination\Paginator;
use Illuminate\Support\Facades\Schema;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 use Request;
 use BackendMenu;
 use BackendAuth;
+use Backend\Models\UserRole;
 use Twig\Extension\SandboxExtension;
 use Twig\Environment as TwigEnvironment;
 use System\Classes\MailManager;
@@ -417,19 +418,23 @@
             $manager->registerPermissions('October.System', [
                 'system.manage_updates' => [
                     'label' => 'system::lang.permissions.manage_software_updates',
-                    'tab' => 'system::lang.permissions.name'
+                    'tab' => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'system.access_logs' => [
                     'label' => 'system::lang.permissions.access_logs',
-                    'tab' => 'system::lang.permissions.name'
+                    'tab' => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'system.manage_mail_settings' => [
                     'label' => 'system::lang.permissions.manage_mail_settings',
-                    'tab' => 'system::lang.permissions.name'
+                    'tab' => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'system.manage_mail_templates' => [
                     'label' => 'system::lang.permissions.manage_mail_templates',
-                    'tab' => 'system::lang.permissions.name'
+                    'tab' => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ]
             ]);
         });
```
