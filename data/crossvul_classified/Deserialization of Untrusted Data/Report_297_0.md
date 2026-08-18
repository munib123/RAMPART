# CrossVul Fix Pair: Deserialization of Untrusted Data in c
**Pair ID:** 297_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `297_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.


static void swoole_serialize_object(seriaString *buffer, zval *zvalue, size_t start);
static void swoole_serialize_arr(seriaString *buffer, zend_array *zvalue);
static void* swoole_unserialize_arr(void *buffer, zval *zvalue, uint32_t num, long flag);
static void* swoole_unserialize_object(void *buffer, zval *return_value, zend_uchar bucket_len, zval *args, long flag);

static PHP_METHOD(swoole_serialize, pack);
static PHP_METHOD(swoole_serialize, unpack);


static const zend_function_entry swoole_serialize_methods[] = {
    PHP_ME(swoole_serialize, pack, arginfo_swoole_serialize_pack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_serialize, unpack, arginfo_swoole_serialize_unpack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

zend_class_entry swoole_serialize_ce;
zend_class_entry *swoole_serialize_class_entry_ptr;

#define SWOOLE_SERI_EOF "EOF"

static struct _swSeriaG swSeriaG;

void swoole_serialize_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_serialize_ce, "swoole_serialize", "Swoole\\Serialize", swoole_serialize_methods);
    swoole_serialize_class_entry_ptr = zend_register_internal_class(&swoole_serialize_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_serialize, "Swoole\\Serialize");

    //    ZVAL_STRING(&swSeriaG.sleep_fname, "__sleep");
    zend_string *zstr_sleep = zend_string_init("__sleep", sizeof ("__sleep") - 1, 1);
    zend_string *zstr_weekup = zend_string_init("__weekup", sizeof ("__weekup") - 1, 1);
    ZVAL_STR(&swSeriaG.sleep_fname, zstr_sleep);
    ZVAL_STR(&swSeriaG.weekup_fname, zstr_weekup);
    //    ZVAL_STRING(&swSeriaG.weekup_fname, "__weekup");

    memset(&swSeriaG.filter, 0, sizeof (swSeriaG.filter));
    memset(&mini_filter, 0, sizeof (mini_filter));

    REGISTER_LONG_CONSTANT("SWOOLE_FAST_PACK", SW_FAST_PACK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("UNSERIALIZE_OBJECT_TO_ARRAY", UNSERIALIZE_OBJECT_TO_ARRAY, CONST_CS | CONST_PERSISTENT);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,8 +52,10 @@
 zend_class_entry *swoole_serialize_class_entry_ptr;
 
 #define SWOOLE_SERI_EOF "EOF"
+#define CHECK_STEP if(buffer>unseri_buffer_end){ php_error_docref(NULL TSRMLS_CC, E_ERROR, "illegal unserialize data"); return NULL;}
 
 static struct _swSeriaG swSeriaG;
+char *unseri_buffer_end = NULL;
 
 void swoole_serialize_init(int module_number TSRMLS_DC)
 {
@@ -113,6 +115,7 @@
     }
 }
 #ifdef __SSE2__
+
 void CPINLINE swoole_mini_memcpy(void *dst, const void *src, size_t len)
 {
     register unsigned char *dd = (unsigned char*) dst + len;
@@ -120,69 +123,69 @@
     switch (len)
     {
         case 68: *((int*) (dd - 68)) = *((int*) (ss - 68));
-        /* no break */
+            /* no break */
         case 64: *((int*) (dd - 64)) = *((int*) (ss - 64));
-        /* no break */
+            /* no break */
         case 60: *((int*) (dd - 60)) = *((int*) (ss - 60));
-        /* no break */
+            /* no break */
         case 56: *((int*) (dd - 56)) = *((int*) (ss - 56));
-        /* no break */
+            /* no break */
         case 52: *((int*) (dd - 52)) = *((int*) (ss - 52));
-        /* no break */
+            /* no break */
         case 48: *((int*) (dd - 48)) = *((int*) (ss - 48));
-        /* no break */
+            /* no break */
         case 44: *((int*) (dd - 44)) = *((int*) (ss - 44));
-        /* no break */
+            /* no break */
         case 40: *((int*) (dd - 40)) = *((int*) (ss - 40));
-        /* no break */
+            /* no break */
         case 36: *((int*) (dd - 36)) = *((int*) (ss - 36));
-        /* no break */
+            /* no break */
         case 32: *((int*) (dd - 32)) = *((int*) (ss - 32));
-        /* no break */
+            /* no break */
         case 28: *((int*) (dd - 28)) = *((int*) (ss - 28));
-        /* no break */
+            /* no break */
         case 24: *((int*) (dd - 24)) = *((int*) (ss - 24));
-        /* no break */
+            /* no break */
         case 20: *((int*) (dd - 20)) = *((int*) (ss - 20));
-        /* no break */
+            /* no break */
         case 16: *((int*) (dd - 16)) = *((int*) (ss - 16));
-        /* no break */
+            /* no break */
         case 12: *((int*) (dd - 12)) = *((int*) (ss - 12));
-        /* no break */
+            /* no break */
         case 8: *((int*) (dd - 8)) = *((int*) (ss - 8));
-        /* no break */
+            /* no break */
         case 4: *((int*) (dd - 4)) = *((int*) (ss - 4));
             break;
         case 67: *((int*) (dd - 67)) = *((int*) (ss - 67));
-        /* no break */
+            /* no break */
         case 63: *((int*) (dd - 63)) = *((int*) (ss - 63));
-        /* no break */
+            /* no break */
         case 59: *((int*) (dd - 59)) = *((int*) (ss - 59));
-        /* no break */
+            /* no break */
         case 55: *((int*) (dd - 55)) = *((int*) (ss - 55));
-        /* no break */
+            /* no break */
         case 51: *((int*) (dd - 51)) = *((int*) (ss - 51));
-        /* no break */
+            /* no break */
         case 47: *((int*) (dd - 47)) = *((int*) (ss - 47));
-        /* no break */
+            /* no break */
         case 43: *((int*) (dd - 43)) = *((int*) (ss - 43));
-        /* no break */
+            /* no break */
         case 39: *((int*) (dd - 39)) = *((int*) (ss - 39));
-        /* no break */
+            /* no break */
         case 35: *((int*) (dd - 35)) = *((int*) (ss - 35));
-        /* no break */
+            /* no break */
         case 31: *((int*) (dd - 31)) = *((int*) (ss - 31));
-        /* no break */
+            /* no break */
         case 27: *((int*) (dd - 27)) = *((int*) (ss - 27));
-        /* no break */
+            /* no break */
         case 23: *((int*) (dd - 23)) = *((int*) (ss - 23));
-        /* no break */
+            /* no break */
         case 19: *((int*) (dd - 19)) = *((int*) (ss - 19));
-        /* no break */
+            /* no break */
         case 15: *((int*) (dd - 15)) = *((int*) (ss - 15));
-        /* no break */
+            /* no break */
         case 11: *((int*) (dd - 11)) = *((int*) (ss - 11));
-        /* no break */
+            /* no break */
         case 7: *((int*) (dd - 7)) = *((int*) (ss - 7));
             *((int*) (dd - 4)) = *((int*) (ss - 4));
             break;
@@ -190,71 +193,71 @@
             dd[-1] = ss[-1];
             break;
         case 66: *((int*) (dd - 66)) = *((int*) (ss - 66));
-        /* no break */
+            /* no break */
         case 62: *((int*) (dd - 62)) = *((int*) (ss - 62));
-        /* no break */
+            /* no break */
         case 58: *((int*) (dd - 58)) = *((int*) (ss - 58));
-        /* no break */
+            /* no break */
         case 54: *((int*) (dd - 54)) = *((int*) (ss - 54));
-        /* no break */
+            /* no break */
         case 50: *((int*) (dd - 50)) = *((int*) (ss - 50));
-        /* no break */
+            /* no break */
         case 46: *((int*) (dd - 46)) = *((int*) (ss - 46));
-        /* no break */
+            /* no break */
         case 42: *((int*) (dd - 42)) = *((int*) (ss - 42));
-        /* no break */
+            /* no break */
         case 38: *((int*) (dd - 38)) = *((int*) (ss - 38));
-        /* no break */
+            /* no break */
         case 34: *((int*) (dd - 34)) = *((int*) (ss - 34));
-        /* no break */
+            /* no break */
         case 30: *((int*) (dd - 30)) = *((int*) (ss - 30));
-        /* no break */
+            /* no break */
         case 26: *((int*) (dd - 26)) = *((int*) (ss - 26));
-        /* no break */
+            /* no break */
         case 22: *((int*) (dd - 22)) = *((int*) (ss - 22));
-        /* no break */
+            /* no break */
         case 18: *((int*) (dd - 18)) = *((int*) (ss - 18));
-        /* no break */
+            /* no break */
         case 14: *((int*) (dd - 14)) = *((int*) (ss - 14));
-        /* no break */
+            /* no break */
         case 10: *((int*) (dd - 10)) = *((int*) (ss - 10));
-        /* no break */
+            /* no break */
         case 6: *((int*) (dd - 6)) = *((int*) (ss - 6));
-        /* no break */
+            /* no break */
         case 2: *((short*) (dd - 2)) = *((short*) (ss - 2));
             break;
         case 65: *((int*) (dd - 65)) = *((int*) (ss - 65));
-        /* no break */
+            /* no break */
         case 61: *((int*) (dd - 61)) = *((int*) (ss - 61));
-        /* no break */
+            /* no break */
         case 57: *((int*) (dd - 57)) = *((int*) (ss - 57));
-        /* no break */
+            /* no break */
         case 53: *((int*) (dd - 53)) = *((int*) (ss - 53));
-        /* no break */
+            /* no break */
         case 49: *((int*) (dd - 49)) = *((int*) (ss - 49));
-        /* no break */
+            /* no break */
         case 45: *((int*) (dd - 45)) = *((int*) (ss - 45));
-        /* no break */
+            /* no break */
         case 41: *((int*) (dd - 41)) = *((int*) (ss - 41));
-        /* no break */
+            /* no break */
         case 37: *((int*) (dd - 37)) = *((int*) (ss - 37));
-        /* no break */
+            /* no break */
         case 33: *((int*) (dd - 33)) = *((int*) (ss - 33));
-        /* no break */
+            /* no break */
         case 29: *((int*) (dd - 29)) = *((int*) (ss - 29));
-        /* no break */
+            /* no break */
         case 25: *((int*) (dd - 25)) = *((int*) (ss - 25));
-        /* no break */
+            /* no break */
         case 21: *((int*) (dd - 21)) = *((int*) (ss - 21));
-        /* no break */
+            /* no break */
         case 17: *((int*) (dd - 17)) = *((int*) (ss - 17));
-        /* no break */
+            /* no break */
         case 13: *((int*) (dd - 13)) = *((int*) (ss - 13));
-        /* no break */
+            /* no break */
         case 9: *((int*) (dd - 9)) = *((int*) (ss - 9));
-        /* no break */
+            /* no break */
... (diff truncated)
```
