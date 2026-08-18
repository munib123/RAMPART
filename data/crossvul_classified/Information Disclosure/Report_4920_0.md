# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4920_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4920_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php

/**
 * Pure-PHP implementation of AES.
 *
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * NOTE: Since AES.php is (for compatibility and phpseclib-historical reasons) virtually
 * just a wrapper to Rijndael.php you may consider using Rijndael.php instead of
 * to save one include_once().
 *
 * If {@link \phpseclib\Crypt\AES::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
 * {@link \phpseclib\Crypt\AES::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
 * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link \phpseclib\Crypt\AES::setKey() setKey()}
 * is called, again, at which point, it'll be recalculated.
 *
 * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, some functions are available to be called that, in the context of AES, don't
 * make a whole lot of sense.  {@link \phpseclib\Crypt\AES::setBlockLength() setBlockLength()}, for instance.  Calling that function,
 * however possible, won't do anything (AES has a fixed block length whereas Rijndael has a variable one).
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $aes = new \phpseclib\Crypt\AES();
 *
 *    $aes->setKey('abcdefghijklmnop');
 *
 *    $size = 10 * 1024;
 *    $plaintext = '';
 *    for ($i = 0; $i < $size; $i++) {
 *        $plaintext.= 'a';
 *    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,13 +11,13 @@
  * just a wrapper to Rijndael.php you may consider using Rijndael.php instead of
  * to save one include_once().
  *
- * If {@link \phpseclib\Crypt\AES::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
- * {@link \phpseclib\Crypt\AES::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
- * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link \phpseclib\Crypt\AES::setKey() setKey()}
+ * If {@link self::setKeyLength() setKeyLength()} isn't called, it'll be calculated from
+ * {@link self::setKey() setKey()}.  ie. if the key is 128-bits, the key length will be 128-bits.  If it's 136-bits
+ * it'll be null-padded to 192-bits and 192 bits will be the key length until {@link self::setKey() setKey()}
  * is called, again, at which point, it'll be recalculated.
  *
  * Since \phpseclib\Crypt\AES extends \phpseclib\Crypt\Rijndael, some functions are available to be called that, in the context of AES, don't
- * make a whole lot of sense.  {@link \phpseclib\Crypt\AES::setBlockLength() setBlockLength()}, for instance.  Calling that function,
+ * make a whole lot of sense.  {@link self::setBlockLength() setBlockLength()}, for instance.  Calling that function,
  * however possible, won't do anything (AES has a fixed block length whereas Rijndael has a variable one).
  *
  * Here's a short example of how to use this library:
@@ -67,7 +67,7 @@
      *
      * @see \phpseclib\Crypt\Rijndael::setBlockLength()
      * @access public
-     * @param Integer $length
+     * @param int $length
      */
     function setBlockLength($length)
     {
@@ -82,7 +82,7 @@
      *
      * @see \phpseclib\Crypt\Rijndael:setKeyLength()
      * @access public
-     * @param Integer $length
+     * @param int $length
      */
     function setKeyLength($length)
     {
@@ -104,7 +104,7 @@
      * @see \phpseclib\Crypt\Rijndael:setKey()
      * @see setKeyLength()
      * @access public
-     * @param String $key
+     * @param string $key
      */
     function setKey($key)
     {
@@ -114,13 +114,13 @@
             $length = strlen($key);
             switch (true) {
                 case $length <= 16:
-                    $this->key_size = 16;
+                    $this->key_length = 16;
                     break;
                 case $length <= 24:
-                    $this->key_size = 24;
+                    $this->key_length = 24;
                     break;
                 default:
-                    $this->key_size = 32;
+                    $this->key_length = 32;
             }
             $this->_setEngine();
         }
```
