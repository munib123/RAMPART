# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in php
**Pair ID:** 4749_2
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4749_2`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```php
Lines 89-129 of the vulnerable file.

               $encrypted, MCRYPT_DECRYPT, substr($key,32,16));
VERIFY($encrypted !== $decrypted);
VS(trim((string)$decrypted), $CC);

//////////////////////////////////////////////////////////////////////

$key = "123456789012345678901234567890123456789012345678901234567890";
$CC = "4007000000027";
$encrypted =
  mcrypt_ofb(MCRYPT_RIJNDAEL_128, substr($key,0,32),
               $CC, MCRYPT_ENCRYPT, substr($key,32,16));
$decrypted =
  mcrypt_ofb(MCRYPT_RIJNDAEL_128, substr($key,0,32),
               $encrypted, MCRYPT_DECRYPT, substr($key,32,16));
VERIFY($encrypted !== $decrypted);
VS($decrypted, $CC);

//////////////////////////////////////////////////////////////////////

VS(mcrypt_get_block_size("tripledes", "ecb"), 8);
VS(mcrypt_get_cipher_name(MCRYPT_TRIPLEDES), "3DES");
VS(mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_CFB), 16);
VS(mcrypt_get_iv_size("des", "ecb"), 8);
VS(mcrypt_get_key_size("tripledes", "ecb"), 24);

$td = mcrypt_module_open("cast-256", "", "cfb", "");
VS(mcrypt_enc_get_algorithms_name($td), "CAST-256");

$td = mcrypt_module_open("tripledes", "", "ecb", "");
VS(mcrypt_enc_get_block_size($td), 8);

$td = mcrypt_module_open("cast-256", "", "cfb", "");
VS(mcrypt_enc_get_iv_size($td), 16);

$td = mcrypt_module_open("tripledes", "", "ecb", "");
VS(mcrypt_enc_get_key_size($td), 24);

$td = mcrypt_module_open("cast-256", "", "cfb", "");
VS(mcrypt_enc_get_modes_name($td), "CFB");

$td = mcrypt_module_open("rijndael-256", "", "ecb", "");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,6 +106,7 @@
 //////////////////////////////////////////////////////////////////////
 
 VS(mcrypt_get_block_size("tripledes", "ecb"), 8);
+mcrypt_get_block_size("tripledes");
 VS(mcrypt_get_cipher_name(MCRYPT_TRIPLEDES), "3DES");
 VS(mcrypt_get_iv_size(MCRYPT_CAST_256, MCRYPT_MODE_CFB), 16);
 VS(mcrypt_get_iv_size("des", "ecb"), 8);
```
