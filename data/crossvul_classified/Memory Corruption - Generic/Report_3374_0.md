# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3374_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3374_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 4027-4067 of the vulnerable file.

      if (r < 0) return r;
    }
  }

  *state = CCS_VALUE;
  *type  = CCV_CLASS;
  return 0;
}

static int
next_state_val(CClassNode* cc, OnigCodePoint *vs, OnigCodePoint v,
	       int* vs_israw, int v_israw,
	       enum CCVALTYPE intype, enum CCVALTYPE* type,
	       enum CCSTATE* state, ScanEnv* env)
{
  int r;

  switch (*state) {
  case CCS_VALUE:
    if (*type == CCV_SB) {
      BITSET_SET_BIT(cc->bs, (int )(*vs));
    }
    else if (*type == CCV_CODE_POINT) {
      r = add_code_range(&(cc->mbuf), env, *vs, *vs);
      if (r < 0) return r;
    }
    break;

  case CCS_RANGE:
    if (intype == *type) {
      if (intype == CCV_SB) {
        if (*vs > 0xff || v > 0xff)
          return ONIGERR_INVALID_CODE_POINT_VALUE;

        if (*vs > v) {
          if (IS_SYNTAX_BV(env->syntax, ONIG_SYN_ALLOW_EMPTY_RANGE_IN_CC))
            goto ccs_range_end;
          else
            return ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS;
        }
        bitset_set_range(cc->bs, (int )*vs, (int )v);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4044,6 +4044,9 @@
   switch (*state) {
   case CCS_VALUE:
     if (*type == CCV_SB) {
+      if (*vs > 0xff)
+          return ONIGERR_INVALID_CODE_POINT_VALUE;
+
       BITSET_SET_BIT(cc->bs, (int )(*vs));
     }
     else if (*type == CCV_CODE_POINT) {
```
