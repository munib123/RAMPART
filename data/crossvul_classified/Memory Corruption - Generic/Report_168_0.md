# CrossVul Fix Pair: Access of Uninitialized Pointer in c
**Pair ID:** 168_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-824
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `168_0`)

## Vulnerability Information & PoC

## Description
Access of Uninitialized Pointer - If the pointer contains an uninitialized value, then the value might not point to a valid memory location.

## Vulnerable Code
```c
Lines 262-302 of the vulnerable file.

      c1 = c1->super;
      c0 = c0->super;
    }
    c1->super = mrb_class_ptr(mrb_obj_dup(mrb, mrb_obj_value(c0)));
    c1->super->flags |= MRB_FLAG_IS_ORIGIN;
  }
  if (sc->mt) {
    dc->mt = kh_copy(mt, mrb, sc->mt);
  }
  else {
    dc->mt = kh_init(mt, mrb);
  }
  dc->super = sc->super;
  MRB_SET_INSTANCE_TT(dc, MRB_INSTANCE_TT(sc));
}

static void
init_copy(mrb_state *mrb, mrb_value dest, mrb_value obj)
{
  switch (mrb_type(obj)) {
    case MRB_TT_CLASS:
    case MRB_TT_MODULE:
      copy_class(mrb, dest, obj);
      mrb_iv_copy(mrb, dest, obj);
      mrb_iv_remove(mrb, dest, mrb_intern_lit(mrb, "__classname__"));
      break;
    case MRB_TT_OBJECT:
    case MRB_TT_SCLASS:
    case MRB_TT_HASH:
    case MRB_TT_DATA:
    case MRB_TT_EXCEPTION:
      mrb_iv_copy(mrb, dest, obj);
      break;
    case MRB_TT_ISTRUCT:
      mrb_istruct_copy(dest, obj);
      break;

    default:
      break;
  }
  mrb_funcall(mrb, dest, "initialize_copy", 1, obj);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -279,6 +279,9 @@
 init_copy(mrb_state *mrb, mrb_value dest, mrb_value obj)
 {
   switch (mrb_type(obj)) {
+    case MRB_TT_ICLASS:
+      copy_class(mrb, dest, obj);
+      return;
     case MRB_TT_CLASS:
     case MRB_TT_MODULE:
       copy_class(mrb, dest, obj);
```
