# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 2455_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2455_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 299-339 of the vulnerable file.

        // Initialize Locale if set and configured.
        if ($this['language']->enabled() && $this['config']->get('system.languages.override_locale')) {
            $language = $this['language']->getLanguage();
            setlocale(LC_ALL, \strlen($language) < 3 ? ($language . '_' . strtoupper($language)) : $language);
        } elseif ($this['config']->get('system.default_locale')) {
            setlocale(LC_ALL, $this['config']->get('system.default_locale'));
        }
    }

    /**
     * Redirect browser to another location.
     *
     * @param string $route Internal route.
     * @param int    $code  Redirection code (30x)
     */
    public function redirect($route, $code = null)
    {
        /** @var Uri $uri */
        $uri = $this['uri'];

        //Check for code in route
        $regex = '/.*(\[(30[1-7])\])$/';
        preg_match($regex, $route, $matches);
        if ($matches) {
            $route = str_replace($matches[1], '', $matches[0]);
            $code = $matches[2];
        }

        if ($code === null) {
            $code = $this['config']->get('system.pages.redirect_default_code', 302);
        }

        if (isset($this['session'])) {
            $this['session']->close();
        }

        if ($uri->isExternal($route)) {
            $url = $route;
        } else {
            $url = rtrim($uri->rootUrl(), '/') . '/';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -316,7 +316,10 @@
         /** @var Uri $uri */
         $uri = $this['uri'];
 
-        //Check for code in route
+        // Clean route for redirect
+        $route = preg_replace("#^\/[\\\/]+\/#", '/', $route);
+
+         // Check for code in route
         $regex = '/.*(\[(30[1-7])\])$/';
         preg_match($regex, $route, $matches);
         if ($matches) {
```
