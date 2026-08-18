# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1752_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1752_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

#include <ruby.h>
#include <fiddle.h>

VALUE rb_cHandle;

struct dl_handle {
    void *ptr;
    int  open;
    int  enable_close;
};

#ifdef _WIN32
# ifndef _WIN32_WCE
static void *
w32_coredll(void)
{
    MEMORY_BASIC_INFORMATION m;
    memset(&m, 0, sizeof(m));
    if( !VirtualQuery(_errno, &m, sizeof(m)) ) return NULL;
    return m.AllocationBase;
}
# endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,7 @@
 #include <ruby.h>
 #include <fiddle.h>
+
+#define SafeStringValueCStr(v) (rb_check_safe_obj(rb_string_value(&v)), StringValueCStr(v))
 
 VALUE rb_cHandle;
 
@@ -143,11 +145,11 @@
 	cflag = RTLD_LAZY | RTLD_GLOBAL;
 	break;
       case 1:
-	clib = NIL_P(lib) ? NULL : StringValuePtr(lib);
+	clib = NIL_P(lib) ? NULL : SafeStringValueCStr(lib);
 	cflag = RTLD_LAZY | RTLD_GLOBAL;
 	break;
       case 2:
-	clib = NIL_P(lib) ? NULL : StringValuePtr(lib);
+	clib = NIL_P(lib) ? NULL : SafeStringValueCStr(lib);
 	cflag = NUM2INT(flag);
 	break;
       default:
@@ -263,7 +265,7 @@
     return PTR2NUM(fiddle_handle);
 }
 
-static VALUE fiddle_handle_sym(void *handle, const char *symbol);
+static VALUE fiddle_handle_sym(void *handle, VALUE symbol);
 
 /*
  * Document-method: sym
@@ -282,7 +284,7 @@
 	rb_raise(rb_eFiddleError, "closed handle");
     }
 
-    return fiddle_handle_sym(fiddle_handle->ptr, StringValueCStr(sym));
+    return fiddle_handle_sym(fiddle_handle->ptr, sym);
 }
 
 #ifndef RTLD_NEXT
@@ -305,11 +307,11 @@
 static VALUE
 rb_fiddle_handle_s_sym(VALUE self, VALUE sym)
 {
-    return fiddle_handle_sym(RTLD_NEXT, StringValueCStr(sym));
-}
-
-static VALUE
-fiddle_handle_sym(void *handle, const char *name)
+    return fiddle_handle_sym(RTLD_NEXT, sym);
+}
+
+static VALUE
+fiddle_handle_sym(void *handle, VALUE symbol)
 {
 #if defined(HAVE_DLERROR)
     const char *err;
@@ -318,6 +320,7 @@
 # define CHECK_DLERROR
 #endif
     void (*func)();
+    const char *name = SafeStringValueCStr(symbol);
 
     rb_secure(2);
 #ifdef HAVE_DLERROR
@@ -367,7 +370,7 @@
     }
 #endif
     if( !func ){
-	rb_raise(rb_eFiddleError, "unknown symbol \"%s\"", name);
+	rb_raise(rb_eFiddleError, "unknown symbol \"%"PRIsVALUE"\"", symbol);
     }
 
     return PTR2NUM(func);
```
