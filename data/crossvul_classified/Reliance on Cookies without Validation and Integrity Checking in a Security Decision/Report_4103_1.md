# CrossVul Fix Pair: Reliance on Cookies without Validation and Integrity Checking in php
**Pair ID:** 4103_1
**Vulnerability Class:** Reliance on Cookies without Validation and Integrity Checking in a Security Decision
**CWE:** CWE-565
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4103_1`)

## Vulnerability Information & PoC

## Description
Reliance on Cookies without Validation and Integrity Checking - Attackers can easily modify cookies, within the browser or by implementing the client-side code outside of the browser.

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<?php namespace October\Rain\Cookie\Middleware;

use Config;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Cookie\Middleware\EncryptCookies as EncryptCookiesBase;

class EncryptCookies extends EncryptCookiesBase
{
    public function __construct(EncrypterContract $encrypter)
    {
        parent::__construct($encrypter);

        // Find unencrypted cookies as specified by the configuration
        $except = Config::get('cookie.unencryptedCookies', []);

        $this->disableFor($except);
    }

    /**
     * Shift gracefully to unserialized cookies
     * @todo Remove entire method if year >= 2021 or build >= 475
     */
    protected function decryptCookie($name, $cookie)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,11 @@
 <?php namespace October\Rain\Cookie\Middleware;
 
 use Config;
+use Session;
+use October\Rain\Cookie\CookieValuePrefix;
+use Symfony\Component\HttpFoundation\Request;
+use Symfony\Component\HttpFoundation\Response;
+use Illuminate\Contracts\Encryption\DecryptException;
 use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
 use Illuminate\Cookie\Middleware\EncryptCookies as EncryptCookiesBase;
 
@@ -57,4 +62,72 @@
 
         return $decrypted;
     }
+
+    /**
+     * Decrypt the cookies on the request.
+     *
+     * @param  \Symfony\Component\HttpFoundation\Request  $request
+     * @return \Symfony\Component\HttpFoundation\Request
+     */
+    protected function decrypt(Request $request)
+    {
+        foreach ($request->cookies as $key => $cookie) {
+            if ($this->isDisabled($key)) {
+                continue;
+            }
+
+            try {
+                // Decrypt the request-provided cookie
+                $decryptedValue = $this->decryptCookie($key, $cookie);
+
+                // Verify that the decrypted value belongs to this cookie key, use null if it fails
+                $value = CookieValuePrefix::getVerifiedValue($key, $decryptedValue, $this->encrypter->getKey());
+
+                /**
+                 * If the cookie is for the session and the value is a valid Session ID,
+                 * then allow it to pass through even if the validation failed (most likely
+                 * because the upgrade just occurred)
+                 *
+                 * The cookie will be adjusted on the next request
+                 * @todo Remove if year >= 2021 or build >= 475
+                 */
+                if (empty($value) && $key === Config::get('session.cookie') && Session::isValidId($decryptedValue)) {
+                    $value = $decryptedValue;
+                }
+
+                // Set the verified cookie value on the request
+                $request->cookies->set($key, $value);
+            } catch (DecryptException $e) {
+                $request->cookies->set($key, null);
+            }
+        }
+
+        return $request;
+    }
+
+    /**
+     * Encrypt the cookies on an outgoing response.
+     *
+     * @param  \Symfony\Component\HttpFoundation\Response  $response
+     * @return \Symfony\Component\HttpFoundation\Response
+     */
+    protected function encrypt(Response $response)
+    {
+        foreach ($response->headers->getCookies() as $cookie) {
+            if ($this->isDisabled($cookie->getName())) {
+                continue;
+            }
+
+            $response->headers->setCookie($this->duplicate(
+                $cookie,
+                $this->encrypter->encrypt(
+                    // Prefix the cookie value to verify that it belongs to the current cookie
+                    CookieValuePrefix::create($cookie->getName(), $this->encrypter->getKey()) . $cookie->getValue(),
+                    static::serialized($cookie->getName())
+                )
+            ));
+        }
+
+        return $response;
+    }
 }
```
