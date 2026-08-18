# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 84_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `84_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1184-1225 of the vulnerable file.

      regs[a] = val;
      NEXT;
    }

    CASE(OP_SETMCNST) {
      /* A Bx    R(A+1)::Syms(Bx) := R(A) */
      int a = GETARG_A(i);
      int bx = GETARG_Bx(i);
      mrb_const_set(mrb, regs[a+1], syms[bx], regs[a]);
      NEXT;
    }

    CASE(OP_GETUPVAR) {
      /* A B C  R(A) := uvget(B,C) */
      int a = GETARG_A(i);
      int b = GETARG_B(i);
      int c = GETARG_C(i);
      mrb_value *regs_a = regs + a;
      struct REnv *e = uvenv(mrb, c);

      if (!e) {
        *regs_a = mrb_nil_value();
      }
      else {
        *regs_a = e->stack[b];
      }
      NEXT;
    }

    CASE(OP_SETUPVAR) {
      /* A B C  uvset(B,C,R(A)) */
      int a = GETARG_A(i);
      int b = GETARG_B(i);
      int c = GETARG_C(i);

      struct REnv *e = uvenv(mrb, c);

      if (e) {
        mrb_value *regs_a = regs + a;

        if (b < MRB_ENV_STACK_LEN(e)) {
          e->stack[b] = *regs_a;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1201,11 +1201,11 @@
       mrb_value *regs_a = regs + a;
       struct REnv *e = uvenv(mrb, c);
 
-      if (!e) {
+      if (e && b < MRB_ENV_STACK_LEN(e)) {
+        *regs_a = e->stack[b];
+      }
+      else {
         *regs_a = mrb_nil_value();
-      }
-      else {
-        *regs_a = e->stack[b];
       }
       NEXT;
     }
```
