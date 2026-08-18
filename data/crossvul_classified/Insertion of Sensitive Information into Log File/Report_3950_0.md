# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in php
**Pair ID:** 3950_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3950_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php namespace RainLab\Debugbar;

use App;
use Event;
use Config;
use Debugbar;
use BackendAuth;
use System\Classes\PluginBase;
use Illuminate\Foundation\AliasLoader;

/**
 * Debugbar Plugin Information File
 */
class Plugin extends PluginBase
{
    /**
     * @var boolean Determine if this plugin should have elevated privileges.
     */
    public $elevated = true;

    /**
     * Returns information about this plugin.
     *
     * @return array
     */
    public function pluginDetails()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,13 +3,17 @@
 use App;
 use Event;
 use Config;
-use Debugbar;
 use BackendAuth;
+use Backend\Models\UserRole;
 use System\Classes\PluginBase;
+use System\Classes\CombineAssets;
 use Illuminate\Foundation\AliasLoader;
 
 /**
  * Debugbar Plugin Information File
+ *
+ * TODO:
+ * - Fix styling by scoping a html reset to phpdebugbar-openhandler and phpdebugbar
  */
 class Plugin extends PluginBase
 {
@@ -26,10 +30,10 @@
     public function pluginDetails()
     {
         return [
-            'name'        => 'Debugbar',
-            'description' => 'Debugbar integration for OctoberCMS.',
+            'name'        => 'rainlab.debugbar::lang.plugin.name',
+            'description' => 'rainlab.debugbar::lang.plugin.description',
             'author'      => 'RainLab',
-            'icon'        => 'icon-cog',
+            'icon'        => 'icon-bug',
             'homepage'    => 'https://github.com/rainlab/debugbar-plugin'
         ];
     }
@@ -43,7 +47,7 @@
         Config::set('debugbar', Config::get('rainlab.debugbar::config'));
 
         // Service provider
-        App::register('\Barryvdh\Debugbar\ServiceProvider');
+        App::register(\RainLab\Debugbar\Classes\ServiceProvider::class);
 
         // Register alias
         $alias = AliasLoader::getInstance();
@@ -51,15 +55,20 @@
 
         // Register middleware
         if (Config::get('app.debugAjax', false)) {
-            $this->app['Illuminate\Contracts\Http\Kernel']->pushMiddleware('\RainLab\Debugbar\Middleware\Debugbar');
+            $this->app['Illuminate\Contracts\Http\Kernel']->pushMiddleware('\RainLab\Debugbar\Middleware\InterpretsAjaxExceptions');
         }
 
+        // Add styling
+        $addResources = function ($controller) {
+            $debugBar = $this->app->make('Barryvdh\Debugbar\LaravelDebugbar');
+            if ($debugBar->isEnabled()) {
+                $controller->addCss(url(Config::get('cms.pluginsPath', '/plugins') . '/rainlab/debugbar/assets/css/debugbar.css'));
+            }
+        };
+        Event::listen('backend.page.beforeDisplay', $addResources, PHP_INT_MAX);
+        Event::listen('cms.page.beforeDisplay', $addResources, PHP_INT_MAX);
+
         Event::listen('cms.page.beforeDisplay', function ($controller, $url, $page) {
-            // Only show for authenticated backend users
-            if (!BackendAuth::check()) {
-                Debugbar::disable();
-            }
-
             // Twig extensions
             $twig = $controller->getTwig();
             if (!$twig->hasExtension(\Barryvdh\Debugbar\Twig\Extension\Debug::class)) {
@@ -68,4 +77,38 @@
             }
         });
     }
+
+    /**
+     * Register the
+     */
+    public function register()
+    {
+        /*
+         * Register asset bundles
+         */
+        CombineAssets::registerCallback(function ($combiner) {
+            $combiner->registerBundle('$/rainlab/debugbar/assets/css/debugbar.less');
+        });
+    }
+
+    /**
+     * Register the permissions used by the plugin
+     *
+     * @return array
+     */
+    public function registerPermissions()
+    {
+        return [
+            'rainlab.debugbar.access_debugbar' => [
+                'tab' => 'rainlab.debugbar::lang.plugin.name',
+                'label' => 'rainlab.debugbar::lang.plugin.access_debugbar',
+                'roles' => UserRole::CODE_DEVELOPER,
+            ],
+            'rainlab.debugbar.access_stored_requests' => [
+                'tab' => 'rainlab.debugbar::lang.plugin.name',
+                'label' => 'rainlab.debugbar::lang.plugin.access_stored_requests',
+                'roles' => UserRole::CODE_DEVELOPER,
+            ],
+        ];
+    }
 }
```
