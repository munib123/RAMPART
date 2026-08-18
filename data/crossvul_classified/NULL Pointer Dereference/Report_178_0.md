# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 178_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `178_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1746-1787 of the vulnerable file.


  path = mrb_obj_iv_get(mrb, (struct RObject*)c, nsym);
  if (mrb_nil_p(path)) {
    /* no name (yet) */
    return mrb_class_find_path(mrb, c);
  }
  else if (mrb_symbol_p(path)) {
    /* toplevel class/module */
    const char *str;
    mrb_int len;

    str = mrb_sym2name_len(mrb, mrb_symbol(path), &len);
    return mrb_str_new(mrb, str, len);
  }
  return mrb_str_dup(mrb, path);
}

MRB_API struct RClass*
mrb_class_real(struct RClass* cl)
{
  if (cl == 0)
    return NULL;
  while ((cl->tt == MRB_TT_SCLASS) || (cl->tt == MRB_TT_ICLASS)) {
    cl = cl->super;
  }
  return cl;
}

MRB_API const char*
mrb_class_name(mrb_state *mrb, struct RClass* c)
{
  mrb_value path = mrb_class_path(mrb, c);
  if (mrb_nil_p(path)) {
    path = mrb_str_new_lit(mrb, "#<Class:");
    mrb_str_concat(mrb, path, mrb_ptr_to_str(mrb, c));
    mrb_str_cat_lit(mrb, path, ">");
  }
  return RSTRING_PTR(path);
}

MRB_API const char*
mrb_obj_classname(mrb_state *mrb, mrb_value obj)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1763,10 +1763,10 @@
 MRB_API struct RClass*
 mrb_class_real(struct RClass* cl)
 {
-  if (cl == 0)
-    return NULL;
+  if (cl == 0) return NULL;
   while ((cl->tt == MRB_TT_SCLASS) || (cl->tt == MRB_TT_ICLASS)) {
     cl = cl->super;
+    if (cl == 0) return NULL;
   }
   return cl;
 }
```
