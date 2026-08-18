# CrossVul Fix Pair: Improper Restriction of Excessive Authentication Attempts in php
**Pair ID:** 1228_1
**Vulnerability Class:** Improper Restriction of Authentication Attempts
**CWE:** CWE-307
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1228_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Excessive Authentication Attempts - The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Vulnerable Code
```php
Lines 782-823 of the vulnerable file.

        }

        $userObj->setImage($_FILES['Filedata']['tmp_name']);

        // set content-type to text/html, otherwise (when application/json is sent) chrome will complain in
        // Ext.form.Action.Submit and mark the submission as failed

        $response = $this->adminJson(['success' => true]);
        $response->headers->set('Content-Type', 'text/html');

        return $response;
    }

    /**
     * @Route("/user/renew-2fa-qr-secret", methods={"GET"})
     *
     * @param Request $request
     */
    public function renew2FaSecretAction(Request $request)
    {
        $this->checkCsrfToken($request);

        $user = $this->getAdminUser();
        $proxyUser = $this->getAdminUser(true);

        $twoFactorService = $this->get('scheb_two_factor.security.google_authenticator');
        $newSecret = $twoFactorService->generateSecret();
        $user->setTwoFactorAuthentication('enabled', true);
        $user->setTwoFactorAuthentication('type', 'google');
        $user->setTwoFactorAuthentication('secret', $newSecret);
        $user->save();

        Tool\Session::useSession(function (AttributeBagInterface $adminSession) {
            Tool\Session::regenerateId();
            $adminSession->set('2fa_required', true);
        });

        $twoFactorService = $this->get('scheb_two_factor.security.google_authenticator');
        $url = $twoFactorService->getQRContent($proxyUser);

        $code = new \Endroid\QrCode\QrCode;
        $code->setWriterByName('png');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -799,8 +799,6 @@
      */
     public function renew2FaSecretAction(Request $request)
     {
-        $this->checkCsrfToken($request);
-
         $user = $this->getAdminUser();
         $proxyUser = $this->getAdminUser(true);
 
```
