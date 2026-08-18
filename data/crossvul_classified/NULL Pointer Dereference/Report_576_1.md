# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 576_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `576_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.


#define CHECK_CLASS_VALIDITY(st, mask, str)                             \
    if (st != 0 || mask == 0) {                                         \
        if (st == 0 && mask == 0) {                                     \
            st = set_ldap_error(context, LDAP_OBJECT_CLASS_VIOLATION, OP_SEARCH); \
        }                                                               \
        k5_prependmsg(context, st, str);                                \
        goto cleanup;                                                   \
    }

#define CHECK_NULL(ptr) if (ptr == NULL) {      \
        st = ENOMEM;                            \
        goto cleanup;                           \
    }

#define  STORE16_INT(ptr, val)  store_16_be(val, ptr)
#define  STORE32_INT(ptr, val)  store_32_be(val, ptr)
#define UNSTORE16_INT(ptr, val) (val = load_16_be(ptr))
#define UNSTORE32_INT(ptr, val) (val = load_32_be(ptr))

#define  KDB_TL_USER_INFO      0x7ffe

#define KDB_TL_PRINCTYPE          0x01
#define KDB_TL_PRINCCOUNT         0x02
#define KDB_TL_USERDN             0x03
#define KDB_TL_KEYINFO            0x04
#define KDB_TL_MASK               0x05
/* 0x06 was KDB_TL_CONTAINERDN but is no longer used */
#define KDB_TL_LINKDN             0x07


#define CHECK_LDAP_HANDLE(lcontext)     if (!(ldap_context              \
                                              && ldap_context->server_info_list)) { \
        return KRB5_KDB_DBNOTINITED;                                    \
    }

#define HNDL_LOCK(lcontext) k5_mutex_lock(&lcontext->hndl_lock)
#define HNDL_UNLOCK(lcontext) k5_mutex_unlock(&lcontext->hndl_lock)

/* ldap server info structure */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,7 +141,7 @@
 #define UNSTORE16_INT(ptr, val) (val = load_16_be(ptr))
 #define UNSTORE32_INT(ptr, val) (val = load_32_be(ptr))
 
-#define  KDB_TL_USER_INFO      0x7ffe
+#define  KDB_TL_USER_INFO      0xff
 
 #define KDB_TL_PRINCTYPE          0x01
 #define KDB_TL_PRINCCOUNT         0x02
```
