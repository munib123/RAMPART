# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2897_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2897_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 320-360 of the vulnerable file.

        /*
         * Extensibility
         */
        if ($event = $this->fireSystemEvent('cms.page.init', [$page])) {
            return $event;
        }

        /*
         * Execute AJAX event
         */
        if ($useAjax && $ajaxResponse = $this->execAjaxHandlers()) {
            return $ajaxResponse;
        }

        /*
         * Execute postback handler
         */
        if (
            $useAjax &&
            ($handler = post('_handler')) &&
            ($handlerResponse = $this->runAjaxHandler($handler)) &&
            $handlerResponse !== true
        ) {
            return $handlerResponse;
        }

        /*
         * Execute page lifecycle
         */
        if ($cycleResponse = $this->execPageCycle()) {
            return $cycleResponse;
        }

        /*
         * Extensibility
         */
        if ($event = $this->fireSystemEvent('cms.page.beforeRenderPage', [$page])) {
            $this->pageContents = $event;
        }
        else {
            /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -337,6 +337,7 @@
         if (
             $useAjax &&
             ($handler = post('_handler')) &&
+            ($this->verifyCsrfToken()) &&
             ($handlerResponse = $this->runAjaxHandler($handler)) &&
             $handlerResponse !== true
         ) {
@@ -1355,4 +1356,32 @@
             }
         }
     }
+
+    //
+    // Security
+    //
+
+    /**
+     * Checks the request data / headers for a valid CSRF token.
+     * Returns false if a valid token is not found. Override this
+     * method to disable the check.
+     * @return bool
+     */
+    protected function verifyCsrfToken()
+    {
+        if (!Config::get('cms.enableCsrfProtection')) {
+            return true;
+        }
+
+        if (in_array(Request::method(), ['HEAD', 'GET', 'OPTIONS'])) {
+            return true;
+        }
+
+        $token = Request::input('_token') ?: Request::header('X-CSRF-TOKEN');
+
+        return hash_equals(
+            Session::token(),
+            $token
+        );
+    }
 }
```
