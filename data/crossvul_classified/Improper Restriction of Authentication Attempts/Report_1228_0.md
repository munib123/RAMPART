# CrossVul Fix Pair: Improper Restriction of Excessive Authentication Attempts in php
**Pair ID:** 1228_0
**Vulnerability Class:** Improper Restriction of Authentication Attempts
**CWE:** CWE-307
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1228_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Excessive Authentication Attempts - The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Vulnerable Code
```php
Lines 208-250 of the vulnerable file.

        }
    }

    /**
     * @return ViewModel
     */
    protected function buildLoginPageViewModel()
    {
        $bundleManager = $this->get('pimcore.extension.bundle_manager');

        $view = new ViewModel([
            'config' => Config::getSystemConfig(),
            'pluginCssPaths' => $bundleManager->getCssPaths()
        ]);

        return $view;
    }

    /**
     * @Route("/login/2fa", name="pimcore_admin_2fa")
     *
     * @param Request $request
     *
     * @TemplatePhp()
     */
    public function twoFactorAuthenticationAction(Request $request)
    {
        $view = $this->buildLoginPageViewModel();

        if ($request->hasSession()) {
            $session = $request->getSession();
            $authException = $session->get(Security::AUTHENTICATION_ERROR);
            if ($authException instanceof AuthenticationException) {
                $session->remove(Security::AUTHENTICATION_ERROR);

                $view->error = $authException->getMessage();
            }
        } else {
            $view->error = 'No session available, it either timed out or cookies are not enabled.';
        }

        return $view;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -225,22 +225,25 @@
 
     /**
      * @Route("/login/2fa", name="pimcore_admin_2fa")
-     *
-     * @param Request $request
-     *
-     * @TemplatePhp()
-     */
-    public function twoFactorAuthenticationAction(Request $request)
+     * @TemplatePhp()
+     */
+    public function twoFactorAuthenticationAction(Request $request, BruteforceProtectionHandler $bruteforceProtectionHandler)
     {
         $view = $this->buildLoginPageViewModel();
 
         if ($request->hasSession()) {
+
+            // we have to call the check here manually, because BruteforceProtectionListener uses the 'username' from the request
+            $bruteforceProtectionHandler->checkProtection($this->getAdminUser()->getName(), $request);
+
             $session = $request->getSession();
             $authException = $session->get(Security::AUTHENTICATION_ERROR);
             if ($authException instanceof AuthenticationException) {
                 $session->remove(Security::AUTHENTICATION_ERROR);
 
                 $view->error = $authException->getMessage();
+
+                $bruteforceProtectionHandler->addEntry($this->getAdminUser()->getName(), $request);
             }
         } else {
             $view->error = 'No session available, it either timed out or cookies are not enabled.';
```
