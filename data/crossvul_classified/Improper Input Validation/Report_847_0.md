# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 847_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `847_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 891-931 of the vulnerable file.

  }
  return ret;
}

static bool php_mb_parse_encoding(const Variant& encoding,
                                  mbfl_encoding ***return_list,
                                  int *return_size, bool persistent) {
  bool ret;
  if (encoding.isArray()) {
    ret = php_mb_parse_encoding_array(encoding.toArray(),
                                      return_list, return_size,
                                      persistent ? 1 : 0);
  } else {
    String enc = encoding.toString();
    ret = php_mb_parse_encoding_list(enc.data(), enc.size(),
                                     return_list, return_size,
                                     persistent ? 1 : 0);
  }
  if (!ret) {
    if (return_list && *return_list) {
      free(*return_list);
      *return_list = nullptr;
    }
    return_size = 0;
  }
  return ret;
}

static int php_mb_nls_get_default_detect_order_list(mbfl_no_language lang,
                                                    mbfl_no_encoding **plist,
                                                    int* plist_size) {
  size_t i;
  *plist = (mbfl_no_encoding *) php_mb_default_identify_list_neut;
  *plist_size = sizeof(php_mb_default_identify_list_neut) /
    sizeof(php_mb_default_identify_list_neut[0]);

  for (i = 0; i < sizeof(php_mb_default_identify_list) /
         sizeof(php_mb_default_identify_list[0]); i++) {
    if (php_mb_default_identify_list[i].lang == lang) {
      *plist = php_mb_default_identify_list[i].list;
      *plist_size = php_mb_default_identify_list[i].list_size;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -908,7 +908,7 @@
   }
   if (!ret) {
     if (return_list && *return_list) {
-      free(*return_list);
+      req::free(*return_list);
       *return_list = nullptr;
     }
     return_size = 0;
```
