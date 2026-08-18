# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 324_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `324_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 84-124 of the vulnerable file.

/* Data passed in the *priv argument for LookupModMask. */
typedef struct {
    const struct xkb_mod_set *mods;
    enum mod_type mod_type;
} LookupModMaskPriv;

static bool
LookupModMask(struct xkb_context *ctx, const void *priv, xkb_atom_t field,
              enum expr_value_type type, xkb_mod_mask_t *val_rtrn)
{
    const char *str;
    xkb_mod_index_t ndx;
    const LookupModMaskPriv *arg = priv;
    const struct xkb_mod_set *mods = arg->mods;
    enum mod_type mod_type = arg->mod_type;

    if (type != EXPR_TYPE_INT)
        return false;

    str = xkb_atom_text(ctx, field);

    if (istreq(str, "all")) {
        *val_rtrn  = MOD_REAL_MASK_ALL;
        return true;
    }

    if (istreq(str, "none")) {
        *val_rtrn = 0;
        return true;
    }

    ndx = XkbModNameToIndex(mods, field, mod_type);
    if (ndx == XKB_MOD_INVALID)
        return false;

    *val_rtrn = (1u << ndx);
    return true;
}

bool
ExprResolveBoolean(struct xkb_context *ctx, const ExprDef *expr,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,6 +101,8 @@
         return false;
 
     str = xkb_atom_text(ctx, field);
+    if (!str)
+        return false;
 
     if (istreq(str, "all")) {
         *val_rtrn  = MOD_REAL_MASK_ALL;
```
