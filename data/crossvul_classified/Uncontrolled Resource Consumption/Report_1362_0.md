# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1362_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1362_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 3273-3313 of the vulnerable file.

    }
    *ret = intv;

    return EXIT_SUCCESS;

error:
    while (intv) {
        tmp_intv = intv->next;
        free(intv);
        intv = tmp_intv;
    }
    while (local_intv) {
        tmp_local_intv = local_intv->next;
        free(local_intv);
        local_intv = tmp_local_intv;
    }

    return -1;
}

/**
 * @brief Resolve a typedef, return only resolved typedefs if derived. If leafref, it must be
 * resolved for this function to return it. Does not log.
 *
 * @param[in] name Typedef name.
 * @param[in] mod_name Typedef name module name.
 * @param[in] module Main module.
 * @param[in] parent Parent of the resolved type definition.
 * @param[out] ret Pointer to the resolved typedef. Can be NULL.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on forward reference, -1 on error.
 */
int
resolve_superior_type(const char *name, const char *mod_name, const struct lys_module *module,
                      const struct lys_node *parent, struct lys_tpdf **ret)
{
    int i, j;
    struct lys_tpdf *tpdf, *match;
    int tpdf_size;

    if (!mod_name) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3290,6 +3290,32 @@
     return -1;
 }
 
+static int
+resolve_superior_type_check(struct lys_type *type)
+{
+    uint32_t i;
+
+    if (type->base == LY_TYPE_DER) {
+        /* check that the referenced typedef is resolved */
+        return EXIT_FAILURE;
+    } else if (type->base == LY_TYPE_UNION) {
+        /* check that all union types are resolved */
+        for (i = 0; i < type->info.uni.count; ++i) {
+            if (resolve_superior_type_check(&type->info.uni.types[i])) {
+                return EXIT_FAILURE;
+            }
+        }
+    } else if (type->base == LY_TYPE_LEAFREF) {
+        /* check there is path in some derived type */
+        while (!type->info.lref.path) {
+            assert(type->der);
+            type = &type->der->type;
+        }
+    }
+
+    return EXIT_SUCCESS;
+}
+
 /**
  * @brief Resolve a typedef, return only resolved typedefs if derived. If leafref, it must be
  * resolved for this function to return it. Does not log.
@@ -3369,9 +3395,9 @@
             }
 
             for (i = 0; i < tpdf_size; i++) {
-                if (!strcmp(tpdf[i].name, name) && tpdf[i].type.base > 0) {
+                if (!strcmp(tpdf[i].name, name)) {
                     match = &tpdf[i];
-                    goto check_leafref;
+                    goto check_typedef;
                 }
             }
 
@@ -3387,33 +3413,31 @@
 
     /* search in top level typedefs */
     for (i = 0; i < module->tpdf_size; i++) {
-        if (!strcmp(module->tpdf[i].name, name) && module->tpdf[i].type.base > 0) {
+        if (!strcmp(module->tpdf[i].name, name)) {
             match = &module->tpdf[i];
-            goto check_leafref;
+            goto check_typedef;
         }
     }
 
     /* search in submodules */
     for (i = 0; i < module->inc_size && module->inc[i].submodule; i++) {
         for (j = 0; j < module->inc[i].submodule->tpdf_size; j++) {
-            if (!strcmp(module->inc[i].submodule->tpdf[j].name, name) && module->inc[i].submodule->tpdf[j].type.base > 0) {
+            if (!strcmp(module->inc[i].submodule->tpdf[j].name, name)) {
                 match = &module->inc[i].submodule->tpdf[j];
-                goto check_leafref;
+                goto check_typedef;
             }
         }
     }
 
     return EXIT_FAILURE;
 
-check_leafref:
+check_typedef:
+    if (resolve_superior_type_check(&match->type)) {
+        return EXIT_FAILURE;
+    }
+
     if (ret) {
         *ret = match;
-    }
-    if (match->type.base == LY_TYPE_LEAFREF) {
-        while (!match->type.info.lref.path) {
-            match = match->type.der;
-            assert(match);
-        }
     }
     return EXIT_SUCCESS;
 }
```
