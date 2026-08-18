# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 2634_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2634_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 387-428 of the vulnerable file.

     * to compare a string with a secret that shouldn't be leaked, i.e. when verifying passwords, one-time codes, etc.
     *
     * @param string $known A known string.
     * @param string $user A user-provided string to compare with the known string.
     *
     * @return bool True if both strings are equal, false otherwise.
     */
    public static function secureCompare($known, $user)
    {
        if (function_exists('hash_equals')) {
            // use hash_equals() if available (PHP >= 5.6)
            return hash_equals($known, $user);
        }

        // compare manually in constant time
        $len = mb_strlen($known, '8bit'); // see mbstring.func_overload
        if ($len !== mb_strlen($user, '8bit')) {
            return false; // length differs
        }
        $diff = 0;
        for ($i = 0; $i < $len; ++$i) {
            $diff |= $known[$i] ^ $user[$i];
        }
        // if all the bytes in $a and $b are identical, $diff should be equal to 0
        return $diff === 0;
    }


    /**
     * This function checks if a password is valid
     *
     * @param string $hash The password as it appears in password file, optionally prepended with algorithm.
     * @param string $password The password to check in clear.
     *
     * @return boolean True if the hash corresponds with the given password, false otherwise.
     * @throws \InvalidArgumentException If the input parameters are not strings.
     * @throws \SimpleSAML_Error_Exception If the algorithm specified is not supported.
     *
     * @author Dyonisius Visser, TERENA <visser@terena.org>
     */
    public static function pwValid($hash, $password)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -404,8 +404,8 @@
             return false; // length differs
         }
         $diff = 0;
-        for ($i = 0; $i < $len; ++$i) {
-            $diff |= $known[$i] ^ $user[$i];
+        for ($i = 0; $i < $len; $i++) {
+            $diff |= ord($known[$i]) ^ ord($user[$i]);
         }
         // if all the bytes in $a and $b are identical, $diff should be equal to 0
         return $diff === 0;
```
