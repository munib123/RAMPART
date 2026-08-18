# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 102-142 of the vulnerable file.

        $this->assign("oaTemplateDir", MAX_PATH.'/lib/templates/admin/');

        //for pluggable page elements
        //- plugins may need to refrence their JS in OXP page templates
        $this->assign("adminPluginWebPath", MAX::constructURL(MAX_URL_ADMIN, 'plugins'));

        //- plugins may need to inject their own
        //template based elements into normal templates
        $this->assign("pluginBaseDir", MAX_PATH.'/www/admin/plugins/');
        $this->assign("pluginTemplateDir", '/templates/');

        /**
         * CVE-2013-5954
         *
         * Register the helper method to allow the the required session token to
         * be placed into GET method calls for CRUD operations in templates. See
         * OA_Permission::checkSessionToken() method for details.
         */
        $this->register_function('rv_add_session_token', array('OA_Admin_Template', '_add_session_token'));

    }

    /**
     * CVE-2013-5954
     *
     * Helper method to allow the the required session token to be placed
     * into GET method calls for CRUD operations in templates. See
     * OA_Permission::checkSessionToken() method for details.
     */
    static public function _add_session_token()
    {
        return 'token=' . urlencode(phpAds_SessionGetToken());
    }

    /**
     * A method to set a cache id for the current page
     *
     * @param mixed $cacheId Either a string or an array of parameters
     */
    function setCacheId($cacheId = null)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,6 +119,8 @@
          */
         $this->register_function('rv_add_session_token', array('OA_Admin_Template', '_add_session_token'));
 
+        // Also assign a template variable for other usages
+        $this->assign("csrfToken", phpAds_SessionGetToken());
     }
 
     /**
```
