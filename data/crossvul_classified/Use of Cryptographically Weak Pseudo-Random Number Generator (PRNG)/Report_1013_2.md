# CrossVul Fix Pair: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in php
**Pair ID:** 1013_2
**Vulnerability Class:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-338
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1013_2`)

## Vulnerability Information & PoC

## Description
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.

## Vulnerable Code
```php
Lines 211-251 of the vulnerable file.


/*
 * |--------------------------------------------------------------------------
 * | Cache Directory Path
 * |--------------------------------------------------------------------------
 * |
 * | Leave this BLANK unless you would like to set something other than the default
 * | system/cache/ folder. Use a full server path with trailing slash.
 * |
 */
$config ['cache_path'] = '';
/*
 * |--------------------------------------------------------------------------
 * | Private Key
 * |--------------------------------------------------------------------------
 * |
 * | ASTPP Using private key for encryption/decryption of password.
 * | MUST set private key with 32 characters.
 * |
 */
$config ['private_key'] = '8YSDaBtDHAB3EQkxPAyTz2I5DttzA9uR';
/*
 * |--------------------------------------------------------------------------
 * | Encryption Key
 * |--------------------------------------------------------------------------
 * |
 * | If you use the Encryption class or the Session class you
 * | MUST set an encryption key. See the user guide for info.
 * |
 */
$config ['encryption_key'] = 'r)fddEw232f';

/*
 * |--------------------------------------------------------------------------
 * | Session Variables
 * |------------------------------------------------------k--------------------
 * |
 * | 'sess_cookie_name' = the name you want for the cookie
 * | 'sess_expiration' = the number of SECONDS you want the session to last.
 * | by default sessions last 7200 seconds (two hours). Set to zero for no expiration.
 * | 'sess_expire_on_close' = Whether to cause the session to expire automatically
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -228,7 +228,7 @@
  * | MUST set private key with 32 characters.
  * |
  */
-$config ['private_key'] = '8YSDaBtDHAB3EQkxPAyTz2I5DttzA9uR';
+$config ['private_key'] = $astpp_config ['PRIVATE_KEY'];
 /*
  * |--------------------------------------------------------------------------
  * | Encryption Key
@@ -238,8 +238,7 @@
  * | MUST set an encryption key. See the user guide for info.
  * |
  */
-$config ['encryption_key'] = 'r)fddEw232f';
-
+$config ['encryption_key'] = $astpp_config ['ENCRYPTION_KEY'];
 /*
  * |--------------------------------------------------------------------------
  * | Session Variables
```
