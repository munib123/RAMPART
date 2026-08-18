# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5507_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5507_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1489-1523 of the vulnerable file.

int subvert;
{
    struct inflate_state FAR *state;

    if (strm == Z_NULL || strm->state == Z_NULL) return Z_STREAM_ERROR;
    state = (struct inflate_state FAR *)strm->state;
#ifdef INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR
    state->sane = !subvert;
    return Z_OK;
#else
    state->sane = 1;
    return Z_DATA_ERROR;
#endif
}

long ZEXPORT inflateMark(strm)
z_streamp strm;
{
    struct inflate_state FAR *state;

    if (strm == Z_NULL || strm->state == Z_NULL) return -1L << 16;
    state = (struct inflate_state FAR *)strm->state;
    return ((long)(state->back) << 16) +
        (state->mode == COPY ? state->length :
            (state->mode == MATCH ? state->was - state->length : 0));
}

unsigned long ZEXPORT inflateCodesUsed(strm)
z_streamp strm;
{
    struct inflate_state FAR *state;
    if (strm == Z_NULL || strm->state == Z_NULL) return -1L;
    state = (struct inflate_state FAR *)strm->state;
    return state->next - state->codes;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1506,9 +1506,10 @@
 {
     struct inflate_state FAR *state;
 
-    if (strm == Z_NULL || strm->state == Z_NULL) return -1L << 16;
+    if (strm == Z_NULL || strm->state == Z_NULL)
+        return (long)(((unsigned long)0 - 1) << 16);
     state = (struct inflate_state FAR *)strm->state;
-    return ((long)(state->back) << 16) +
+    return (long)(((unsigned long)((long)state->back)) << 16) +
         (state->mode == COPY ? state->length :
             (state->mode == MATCH ? state->was - state->length : 0));
 }
```
