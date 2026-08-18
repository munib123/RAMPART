# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 177_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `177_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 167-207 of the vulnerable file.


  for (ci = c->ci; ci >= c->cibase; ci--) {
    if (ci->acc < 0) {
      mrb_raise(mrb, E_FIBER_ERROR, "can't cross C function boundary");
    }
  }
}

static void
fiber_switch_context(mrb_state *mrb, struct mrb_context *c)
{
  c->status = MRB_FIBER_RUNNING;
  mrb->c = c;
}

static mrb_value
fiber_switch(mrb_state *mrb, mrb_value self, mrb_int len, const mrb_value *a, mrb_bool resume, mrb_bool vmexec)
{
  struct mrb_context *c = fiber_check(mrb, self);
  struct mrb_context *old_c = mrb->c;
  mrb_value value;

  fiber_check_cfunc(mrb, c);
  if (resume && c->status == MRB_FIBER_TRANSFERRED) {
    mrb_raise(mrb, E_FIBER_ERROR, "resuming transferred fiber");
  }
  if (c->status == MRB_FIBER_RUNNING || c->status == MRB_FIBER_RESUMED) {
    mrb_raise(mrb, E_FIBER_ERROR, "double resume (fib)");
  }
  if (c->status == MRB_FIBER_TERMINATED) {
    mrb_raise(mrb, E_FIBER_ERROR, "resuming dead fiber");
  }
  mrb->c->status = resume ? MRB_FIBER_RESUMED : MRB_FIBER_TRANSFERRED;
  c->prev = resume ? mrb->c : (c->prev ? c->prev : mrb->root_c);
  if (c->status == MRB_FIBER_CREATED) {
    mrb_value *b, *e;

    if (len >= c->stend - c->stack) {
      mrb_raise(mrb, E_FIBER_ERROR, "too many arguments to fiber");
    }
    b = c->stack+1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,26 +184,27 @@
 {
   struct mrb_context *c = fiber_check(mrb, self);
   struct mrb_context *old_c = mrb->c;
+  enum mrb_fiber_state status;
   mrb_value value;
 
   fiber_check_cfunc(mrb, c);
-  if (resume && c->status == MRB_FIBER_TRANSFERRED) {
+  status = c->status;
+  if (resume && status == MRB_FIBER_TRANSFERRED) {
     mrb_raise(mrb, E_FIBER_ERROR, "resuming transferred fiber");
   }
-  if (c->status == MRB_FIBER_RUNNING || c->status == MRB_FIBER_RESUMED) {
+  if (status == MRB_FIBER_RUNNING || status == MRB_FIBER_RESUMED) {
     mrb_raise(mrb, E_FIBER_ERROR, "double resume (fib)");
   }
-  if (c->status == MRB_FIBER_TERMINATED) {
+  if (status == MRB_FIBER_TERMINATED) {
     mrb_raise(mrb, E_FIBER_ERROR, "resuming dead fiber");
   }
-  mrb->c->status = resume ? MRB_FIBER_RESUMED : MRB_FIBER_TRANSFERRED;
+  old_c->status = resume ? MRB_FIBER_RESUMED : MRB_FIBER_TRANSFERRED;
   c->prev = resume ? mrb->c : (c->prev ? c->prev : mrb->root_c);
-  if (c->status == MRB_FIBER_CREATED) {
+  fiber_switch_context(mrb, c);
+  if (status == MRB_FIBER_CREATED) {
     mrb_value *b, *e;
 
-    if (len >= c->stend - c->stack) {
-      mrb_raise(mrb, E_FIBER_ERROR, "too many arguments to fiber");
-    }
+    mrb_stack_extend(mrb, len+2); /* for receiver and (optional) block */
     b = c->stack+1;
     e = b + len;
     while (b<e) {
@@ -215,7 +216,6 @@
   else {
     value = fiber_result(mrb, a, len);
   }
-  fiber_switch_context(mrb, c);
 
   if (vmexec) {
     c->vmexec = TRUE;
```
