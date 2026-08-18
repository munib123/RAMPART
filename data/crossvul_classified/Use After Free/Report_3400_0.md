# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3400_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3400_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 527-567 of the vulnerable file.

}

static inline void
add_gray_list(mrb_state *mrb, mrb_gc *gc, struct RBasic *obj)
{
#ifdef MRB_GC_STRESS
  if (obj->tt > MRB_TT_MAXDEFINE) {
    abort();
  }
#endif
  paint_gray(obj);
  obj->gcnext = gc->gray_list;
  gc->gray_list = obj;
}

static void
mark_context_stack(mrb_state *mrb, struct mrb_context *c)
{
  size_t i;
  size_t e;

  if (c->stack == NULL) return;
  e = c->stack - c->stbase;
  if (c->ci) e += c->ci->nregs;
  if (c->stbase + e > c->stend) e = c->stend - c->stbase;
  for (i=0; i<e; i++) {
    mrb_value v = c->stbase[i];

    if (!mrb_immediate_p(v)) {
      if (mrb_basic_ptr(v)->tt == MRB_TT_FREE) {
        c->stbase[i] = mrb_nil_value();
      }
      else {
        mrb_gc_mark(mrb, mrb_basic_ptr(v));
      }
    }
  }
}

static void
mark_context(mrb_state *mrb, struct mrb_context *c)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -544,6 +544,7 @@
 {
   size_t i;
   size_t e;
+  mrb_value nil;
 
   if (c->stack == NULL) return;
   e = c->stack - c->stbase;
@@ -553,13 +554,13 @@
     mrb_value v = c->stbase[i];
 
     if (!mrb_immediate_p(v)) {
-      if (mrb_basic_ptr(v)->tt == MRB_TT_FREE) {
-        c->stbase[i] = mrb_nil_value();
-      }
-      else {
-        mrb_gc_mark(mrb, mrb_basic_ptr(v));
-      }
-    }
+      mrb_gc_mark(mrb, mrb_basic_ptr(v));
+    }
+  }
+  e = c->stend - c->stbase;
+  nil = mrb_nil_value();
+  for (; i<e; i++) {
+    c->stbase[i] = nil;
   }
 }
 
```
