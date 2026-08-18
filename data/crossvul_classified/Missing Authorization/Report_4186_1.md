# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4186_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4186_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.


use Db;
use App;
use View;
use Event;
use Config;
use Backend;
use Request;
use BackendMenu;
use BackendAuth;
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
use System\Models\EventLog;
use System\Models\MailSetting;
use System\Classes\CombineAssets;
use Backend\Classes\WidgetManager;
use October\Rain\Support\ModuleServiceProvider;
use October\Rain\Router\Helper as RouterHelper;
use Illuminate\Pagination\Paginator;
use Illuminate\Support\Facades\Schema;

class ServiceProvider extends ModuleServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        parent::register('system');

        $this->registerSingletons();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 use System\Twig\Engine as TwigEngine;
 use System\Twig\Loader as TwigLoader;
 use System\Twig\Extension as TwigExtension;
+use System\Twig\SecurityPolicy as TwigSecurityPolicy;
 use System\Models\EventLog;
 use System\Models\MailSetting;
 use System\Classes\CombineAssets;
@@ -27,6 +28,7 @@
 use October\Rain\Router\Helper as RouterHelper;
 use Illuminate\Pagination\Paginator;
 use Illuminate\Support\Facades\Schema;
+use Twig\Extension\SandboxExtension;
 
 class ServiceProvider extends ModuleServiceProvider
 {
@@ -297,6 +299,7 @@
         App::singleton('twig.environment', function ($app) {
             $twig = new TwigEnvironment(new TwigLoader, ['auto_reload' => true]);
             $twig->addExtension(new TwigExtension);
+            $twig->addExtension(new SandboxExtension(new TwigSecurityPolicy, true));
             return $twig;
         });
 
```
