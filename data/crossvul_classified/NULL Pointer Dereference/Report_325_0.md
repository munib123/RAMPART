# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 325_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `325_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 247-287 of the vulnerable file.


    darray_append(info->interps, *new);
    return true;
}

/***====================================================================***/

static bool
ResolveStateAndPredicate(ExprDef *expr, enum xkb_match_operation *pred_rtrn,
                         xkb_mod_mask_t *mods_rtrn, CompatInfo *info)
{
    if (expr == NULL) {
        *pred_rtrn = MATCH_ANY_OR_NONE;
        *mods_rtrn = MOD_REAL_MASK_ALL;
        return true;
    }

    *pred_rtrn = MATCH_EXACTLY;
    if (expr->expr.op == EXPR_ACTION_DECL) {
        const char *pred_txt = xkb_atom_text(info->ctx, expr->action.name);
        if (!LookupString(symInterpretMatchMaskNames, pred_txt, pred_rtrn)) {
            log_err(info->ctx,
                    "Illegal modifier predicate \"%s\"; Ignored\n", pred_txt);
            return false;
        }
        expr = expr->action.args;
    }
    else if (expr->expr.op == EXPR_IDENT) {
        const char *pred_txt = xkb_atom_text(info->ctx, expr->ident.ident);
        if (pred_txt && istreq(pred_txt, "any")) {
            *pred_rtrn = MATCH_ANY;
            *mods_rtrn = MOD_REAL_MASK_ALL;
            return true;
        }
    }

    return ExprResolveModMask(info->ctx, expr, MOD_REAL, &info->mods,
                              mods_rtrn);
}

/***====================================================================***/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -264,7 +264,8 @@
     *pred_rtrn = MATCH_EXACTLY;
     if (expr->expr.op == EXPR_ACTION_DECL) {
         const char *pred_txt = xkb_atom_text(info->ctx, expr->action.name);
-        if (!LookupString(symInterpretMatchMaskNames, pred_txt, pred_rtrn)) {
+        if (!LookupString(symInterpretMatchMaskNames, pred_txt, pred_rtrn) ||
+            !expr->action.args) {
             log_err(info->ctx,
                     "Illegal modifier predicate \"%s\"; Ignored\n", pred_txt);
             return false;
```
