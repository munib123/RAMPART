# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in cpp
**Pair ID:** 4749_0
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4749_0`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```cpp
Lines 440-480 of the vulnerable file.


Variant HHVM_FUNCTION(mcrypt_ecb, const String& cipher, const String& key,
                                  const String& data, const Variant& mode,
                                  const Variant& viv /* = null_string */) {
  raise_deprecated("Function mcrypt_ecb() is deprecated");
  String iv = viv.toString();
  return php_mcrypt_do_crypt(cipher, key, data, "ecb", iv, mode.toInt32(),
                             "mcrypt_ecb");
}

Variant HHVM_FUNCTION(mcrypt_ofb, const String& cipher, const String& key,
                                  const String& data, const Variant& mode,
                                  const Variant& viv /* = null_string */) {
  raise_deprecated("Function mcrypt_ofb() is deprecated");
  String iv = viv.toString();
  return php_mcrypt_do_crypt(cipher, key, data, "ofb", iv, mode.toInt32(),
                             "mcrypt_ofb");
}

Variant HHVM_FUNCTION(mcrypt_get_block_size, const String& cipher,
                                    const Variant& module /* = null_string */) {
  MCRYPT td = mcrypt_module_open((char*)cipher.data(),
                                 (char*)MCG(algorithms_dir).data(),
                                 (char*)module.asCStrRef().data(),
                                 (char*)MCG(modes_dir).data());
  if (td == MCRYPT_FAILED) {
    MCRYPT_OPEN_MODULE_FAILED("mcrypt_get_block_size");
    return false;
  }

  int64_t ret = mcrypt_enc_get_block_size(td);
  mcrypt_module_close(td);
  return ret;
}

Variant HHVM_FUNCTION(mcrypt_get_cipher_name, const String& cipher) {
  MCRYPT td = mcrypt_module_open((char*)cipher.data(),
                                 (char*)MCG(algorithms_dir).data(),
                                 (char*)"ecb",
                                 (char*)MCG(modes_dir).data());
  if (td == MCRYPT_FAILED) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -457,10 +457,10 @@
 }
 
 Variant HHVM_FUNCTION(mcrypt_get_block_size, const String& cipher,
-                                    const Variant& module /* = null_string */) {
+                                             const String& mode) {
   MCRYPT td = mcrypt_module_open((char*)cipher.data(),
                                  (char*)MCG(algorithms_dir).data(),
-                                 (char*)module.asCStrRef().data(),
+                                 (char*)mode.data(),
                                  (char*)MCG(modes_dir).data());
   if (td == MCRYPT_FAILED) {
     MCRYPT_OPEN_MODULE_FAILED("mcrypt_get_block_size");
```
