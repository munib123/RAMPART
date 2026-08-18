# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in php
**Pair ID:** 4749_1
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4749_1`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```php
Lines 280-320 of the vulnerable file.

 *   done, you should free the encryption buffers by calling
 *   mcrypt_generic_deinit(). See mcrypt_module_open() for an example.
 * @param string $data - The data to encrypt.
 *
 * @return string - Returns the encrypted data.
 */
<<__Native>>
function mcrypt_generic(resource $td,
                        string $data): mixed;

/**
 * Gets the block size of the specified cipher
 *
 * @param string $cipher -
 * @param string $mode -
 *
 * @return int - Gets the block size, as an integer.
 */
<<__Native>>
function mcrypt_get_block_size(string $cipher,
                               ?string $mode = null): mixed;

/**
 * Gets the name of the specified cipher
 *
 * @param string $cipher -
 *
 * @return string - This function returns the name of the cipher or FALSE
 *   if the cipher does not exist.
 */
<<__Native>>
function mcrypt_get_cipher_name(string $cipher): mixed;

/**
 * Returns the size of the IV belonging to a specific cipher/mode combination
 *
 * @param string $cipher -
 * @param string $mode - The IV is ignored in ECB mode as this mode does
 *   not require it. You will need to have the same IV (think: starting
 *   point) both at encryption and decryption stages, otherwise your
 *   encryption will fail.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -297,7 +297,7 @@
  */
 <<__Native>>
 function mcrypt_get_block_size(string $cipher,
-                               ?string $mode = null): mixed;
+                               string $mode): mixed;
 
 /**
  * Gets the name of the specified cipher
```
