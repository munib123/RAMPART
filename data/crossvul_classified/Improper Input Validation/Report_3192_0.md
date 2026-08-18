# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3192_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3192_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 637-677 of the vulnerable file.


    case BPLIST_REAL:
        if (*object + (uint64_t)(1 << size) > bplist->offset_table) {
            PLIST_BIN_ERR("%s: BPLIST_REAL data bytes point outside of valid range\n", __func__);
            return NULL;
        }
        return parse_real_node(object, size);

    case BPLIST_DATE:
        if (3 != size) {
            PLIST_BIN_ERR("%s: invalid data size for BPLIST_DATE node\n", __func__);
            return NULL;
        }
        if (*object + (uint64_t)(1 << size) > bplist->offset_table) {
            PLIST_BIN_ERR("%s: BPLIST_DATE data bytes point outside of valid range\n", __func__);
            return NULL;
        }
        return parse_date_node(object, size);

    case BPLIST_DATA:
        if (*object + size > bplist->offset_table) {
            PLIST_BIN_ERR("%s: BPLIST_DATA data bytes point outside of valid range\n", __func__);
            return NULL;
        }
        return parse_data_node(object, size);

    case BPLIST_STRING:
        if (*object + size > bplist->offset_table) {
            PLIST_BIN_ERR("%s: BPLIST_STRING data bytes point outside of valid range\n", __func__);
            return NULL;
        }
        return parse_string_node(object, size);

    case BPLIST_UNICODE:
        if (size*2 < size) {
            PLIST_BIN_ERR("%s: Integer overflow when calculating BPLIST_UNICODE data size.\n", __func__);
            return NULL;
        }
        if (*object + size*2 > bplist->offset_table) {
            PLIST_BIN_ERR("%s: BPLIST_UNICODE data bytes point outside of valid range\n", __func__);
            return NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -654,14 +654,14 @@
         return parse_date_node(object, size);
 
     case BPLIST_DATA:
-        if (*object + size > bplist->offset_table) {
+        if (*object + size < *object || *object + size > bplist->offset_table) {
             PLIST_BIN_ERR("%s: BPLIST_DATA data bytes point outside of valid range\n", __func__);
             return NULL;
         }
         return parse_data_node(object, size);
 
     case BPLIST_STRING:
-        if (*object + size > bplist->offset_table) {
+        if (*object + size < *object || *object + size > bplist->offset_table) {
             PLIST_BIN_ERR("%s: BPLIST_STRING data bytes point outside of valid range\n", __func__);
             return NULL;
         }
@@ -672,7 +672,7 @@
             PLIST_BIN_ERR("%s: Integer overflow when calculating BPLIST_UNICODE data size.\n", __func__);
             return NULL;
         }
-        if (*object + size*2 > bplist->offset_table) {
+        if (*object + size*2 < *object || *object + size*2 > bplist->offset_table) {
             PLIST_BIN_ERR("%s: BPLIST_UNICODE data bytes point outside of valid range\n", __func__);
             return NULL;
         }
@@ -680,7 +680,7 @@
 
     case BPLIST_SET:
     case BPLIST_ARRAY:
-        if (*object + size > bplist->offset_table) {
+        if (*object + size < *object || *object + size > bplist->offset_table) {
             PLIST_BIN_ERR("%s: BPLIST_ARRAY data bytes point outside of valid range\n", __func__);
             return NULL;
         }
@@ -694,8 +694,8 @@
         return parse_uid_node(object, size);
 
     case BPLIST_DICT:
-        if (*object + size > bplist->offset_table) {
-            PLIST_BIN_ERR("%s: BPLIST_REAL data bytes point outside of valid range\n", __func__);
+        if (*object + size < *object || *object + size > bplist->offset_table) {
+            PLIST_BIN_ERR("%s: BPLIST_DICT data bytes point outside of valid range\n", __func__);
             return NULL;
         }
         return parse_dict_node(bplist, object, size);
```
