# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4186_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4186_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php namespace Cms\Classes;

use Cms;
use Url;
use App;
use View;
use Lang;
use Flash;
use Config;
use Session;
use Request;
use Response;
use Exception;
use SystemException;
use BackendAuth;
use Twig\Environment as TwigEnvironment;
use Twig\Cache\FilesystemCache as TwigCacheFilesystem;
use Cms\Twig\Loader as TwigLoader;
use Cms\Twig\DebugExtension;
use Cms\Twig\Extension as CmsTwigExtension;
use Cms\Models\MaintenanceSetting;
use System\Models\RequestLog;
use System\Helpers\View as ViewHelper;
use System\Classes\CombineAssets;
use System\Twig\Extension as SystemTwigExtension;
use October\Rain\Exception\AjaxException;
use October\Rain\Exception\ValidationException;
use October\Rain\Parse\Bracket as TextParser;
use Illuminate\Http\RedirectResponse;

/**
 * The CMS controller class.
 * The controller finds and serves requested pages.
 *
 * @package october\cms
 * @author Alexey Bobkov, Samuel Georges
 */
class Controller
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 use BackendAuth;
 use Twig\Environment as TwigEnvironment;
 use Twig\Cache\FilesystemCache as TwigCacheFilesystem;
+use Twig\Extension\SandboxExtension;
 use Cms\Twig\Loader as TwigLoader;
 use Cms\Twig\DebugExtension;
 use Cms\Twig\Extension as CmsTwigExtension;
@@ -23,6 +24,7 @@
 use System\Helpers\View as ViewHelper;
 use System\Classes\CombineAssets;
 use System\Twig\Extension as SystemTwigExtension;
+use System\Twig\SecurityPolicy;
 use October\Rain\Exception\AjaxException;
 use October\Rain\Exception\ValidationException;
 use October\Rain\Parse\Bracket as TextParser;
@@ -608,6 +610,7 @@
         $this->twig = new TwigEnvironment($this->loader, $options);
         $this->twig->addExtension(new CmsTwigExtension($this));
         $this->twig->addExtension(new SystemTwigExtension);
+        $this->twig->addExtension(new SandboxExtension(new SecurityPolicy, true));
 
         if ($isDebugMode) {
             $this->twig->addExtension(new DebugExtension($this));
```
