# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5526_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5526_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

/* -*- C -*-
 * $Id$
 */

#include <ruby.h>
#include "dl.h"

VALUE rb_cDLHandle;

void
dlhandle_free(struct dl_handle *dlhandle)
{
  if( dlhandle->ptr && dlhandle->open && dlhandle->enable_close ){
    dlclose(dlhandle->ptr);
  }
}

VALUE
rb_dlhandle_close(VALUE self)
{
  struct dl_handle *dlhandle;

  Data_Get_Struct(self, struct dl_handle, dlhandle);
  dlhandle->open = 0;
  return INT2NUM(dlclose(dlhandle->ptr));
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,8 @@
 
 #include <ruby.h>
 #include "dl.h"
+
+#define SafeStringValuePtr(v) (rb_string_value(&v), rb_check_safe_obj(v), RSTRING_PTR(v))
 
 VALUE rb_cDLHandle;
 
@@ -56,11 +58,11 @@
     cflag = RTLD_LAZY | RTLD_GLOBAL;
     break;
   case 1:
-    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);
+    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);
     cflag = RTLD_LAZY | RTLD_GLOBAL;
     break;
   case 2:
-    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);
+    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);
     cflag = NUM2INT(flag);
     break;
   default:
@@ -140,7 +142,7 @@
 
     rb_secure(2);
 
-    name = StringValuePtr(sym);
+    name = SafeStringValuePtr(sym);
 
     Data_Get_Struct(self, struct dl_handle, dlhandle);
     if( ! dlhandle->open ){
```
