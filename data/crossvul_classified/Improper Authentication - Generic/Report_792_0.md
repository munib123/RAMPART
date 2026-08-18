# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 792_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `792_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 103-125 of the vulnerable file.

        return $this->encodeCookie([
            $class,
            base64_encode($username),
            $expires,
            $this->generateCookieHash($class, $username, $expires, $password),
        ]);
    }

    /**
     * Generates a hash for the cookie to ensure it is not being tempered with.
     *
     * @param string $class
     * @param string $username The username
     * @param int    $expires  The Unix timestamp when the cookie expires
     * @param string $password The encoded password
     *
     * @return string
     */
    protected function generateCookieHash($class, $username, $expires, $password)
    {
        return hash_hmac('sha256', $class.$username.$expires.$password, $this->getSecret());
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,6 +120,6 @@
      */
     protected function generateCookieHash($class, $username, $expires, $password)
     {
-        return hash_hmac('sha256', $class.$username.$expires.$password, $this->getSecret());
+        return hash_hmac('sha256', $class.self::COOKIE_DELIMITER.$username.self::COOKIE_DELIMITER.$expires.self::COOKIE_DELIMITER.$password, $this->getSecret());
     }
 }
```
