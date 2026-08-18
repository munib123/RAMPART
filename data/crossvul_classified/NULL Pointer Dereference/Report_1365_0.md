# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1365_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1365_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1584-1625 of the vulnerable file.

error:
    (*new) = NULL;
    lys_extension_instances_free(ctx, result, u, NULL);
    return EXIT_FAILURE;
}

static struct lys_restr *
lys_restr_dup(struct lys_module *mod, struct lys_restr *old, int size, int shallow, struct unres_schema *unres)
{
    struct lys_restr *result;
    int i;

    if (!size) {
        return NULL;
    }

    result = calloc(size, sizeof *result);
    LY_CHECK_ERR_RETURN(!result, LOGMEM(mod->ctx), NULL);

    for (i = 0; i < size; i++) {
        result[i].ext_size = old[i].ext_size;
        lys_ext_dup(mod->ctx, mod, old[i].ext, old[i].ext_size, &result[i], LYEXT_PAR_RESTR, &result[i].ext, shallow, unres);
        result[i].expr = lydict_insert(mod->ctx, old[i].expr, 0);
        result[i].dsc = lydict_insert(mod->ctx, old[i].dsc, 0);
        result[i].ref = lydict_insert(mod->ctx, old[i].ref, 0);
        result[i].eapptag = lydict_insert(mod->ctx, old[i].eapptag, 0);
        result[i].emsg = lydict_insert(mod->ctx, old[i].emsg, 0);
    }

    return result;
}

void
lys_restr_free(struct ly_ctx *ctx, struct lys_restr *restr,
               void (*private_destructor)(const struct lys_node *node, void *priv))
{
    assert(ctx);
    if (!restr) {
        return;
    }

    lys_extension_instances_free(ctx, restr->ext, restr->ext_size, private_destructor);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1601,8 +1601,11 @@
     LY_CHECK_ERR_RETURN(!result, LOGMEM(mod->ctx), NULL);
 
     for (i = 0; i < size; i++) {
-        result[i].ext_size = old[i].ext_size;
-        lys_ext_dup(mod->ctx, mod, old[i].ext, old[i].ext_size, &result[i], LYEXT_PAR_RESTR, &result[i].ext, shallow, unres);
+        /* copying unresolved extensions is not supported */
+        if (unres_schema_find(unres, -1, (void *)&old[i].ext, UNRES_EXT) == -1) {
+            result[i].ext_size = old[i].ext_size;
+            lys_ext_dup(mod->ctx, mod, old[i].ext, old[i].ext_size, &result[i], LYEXT_PAR_RESTR, &result[i].ext, shallow, unres);
+        }
         result[i].expr = lydict_insert(mod->ctx, old[i].expr, 0);
         result[i].dsc = lydict_insert(mod->ctx, old[i].dsc, 0);
         result[i].ref = lydict_insert(mod->ctx, old[i].ref, 0);
```
