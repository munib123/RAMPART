# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 176_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `176_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 331-371 of the vulnerable file.

 *
 *  Some Class(True False Nil Symbol Fixnum Float) Object  cannot clone.
 */
MRB_API mrb_value
mrb_obj_clone(mrb_state *mrb, mrb_value self)
{
  struct RObject *p;
  mrb_value clone;

  if (mrb_immediate_p(self)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "can't clone %S", self);
  }
  if (mrb_type(self) == MRB_TT_SCLASS) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't clone singleton class");
  }
  p = (struct RObject*)mrb_obj_alloc(mrb, mrb_type(self), mrb_obj_class(mrb, self));
  p->c = mrb_singleton_class_clone(mrb, self);
  mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)p->c);
  clone = mrb_obj_value(p);
  init_copy(mrb, clone, self);
  p->flags = mrb_obj_ptr(self)->flags;

  return clone;
}

/* 15.3.1.3.9  */
/*
 *  call-seq:
 *     obj.dup -> an_object
 *
 *  Produces a shallow copy of <i>obj</i>---the instance variables of
 *  <i>obj</i> are copied, but not the objects they reference.
 *  <code>dup</code> copies the frozen state of <i>obj</i>. See also
 *  the discussion under <code>Object#clone</code>. In general,
 *  <code>clone</code> and <code>dup</code> may have different semantics
 *  in descendant classes. While <code>clone</code> is used to duplicate
 *  an object, including its internal state, <code>dup</code> typically
 *  uses the class of the descendant object to create the new instance.
 *
 *  This method may have class-specific behavior.  If so, that
 *  behavior will be documented under the #+initialize_copy+ method of
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,7 +348,7 @@
   mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)p->c);
   clone = mrb_obj_value(p);
   init_copy(mrb, clone, self);
-  p->flags = mrb_obj_ptr(self)->flags;
+  p->flags |= mrb_obj_ptr(self)->flags & MRB_FLAG_IS_FROZEN;
 
   return clone;
 }
```
