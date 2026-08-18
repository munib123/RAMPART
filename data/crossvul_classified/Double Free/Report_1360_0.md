# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1360_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1360_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 4746-4786 of the vulnerable file.

        yang_free_ident_base(module->ident, 0, module->ident_size);
    }
    if (erase_nodes) {
        yang_free_nodes(module->ctx, node);
    }
    for (i = module->augment_size; i < aug_size; ++i) {
        yang_free_augment(module->ctx, &module->augment[i]);
    }
    for (i = module->deviation_size; i < dev_size; ++i) {
        yang_free_deviate(module->ctx, &module->deviation[i], 0);
        free(module->deviation[i].deviate);
        lydict_remove(module->ctx, module->deviation[i].target_name);
        lydict_remove(module->ctx, module->deviation[i].dsc);
        lydict_remove(module->ctx, module->deviation[i].ref);
    }
    return EXIT_FAILURE;
}

int
yang_read_extcomplex_str(struct lys_module *module, struct lys_ext_instance_complex *ext, const char *arg_name,
                         const char *parent_name, char *value, int parent_stmt, LY_STMT stmt)
{
    int c;
    const char **str, ***p = NULL;
    void *reallocated;
    struct lyext_substmt *info;

    c = 0;
    if (stmt == LY_STMT_PREFIX && parent_stmt == LY_STMT_BELONGSTO) {
        /* str contains no NULL value */
        str = lys_ext_complex_get_substmt(LY_STMT_BELONGSTO, ext, &info);
        if (info->cardinality < LY_STMT_CARD_SOME) {
            str++;
        } else {
           /* get the index in the array to add new item */
            p = (const char ***)str;
            for (c = 0; p[0][c + 1]; c++);
            str = p[1];
        }
        str[c] = lydict_insert_zc(module->ctx, value);
    }  else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4763,7 +4763,7 @@
 
 int
 yang_read_extcomplex_str(struct lys_module *module, struct lys_ext_instance_complex *ext, const char *arg_name,
-                         const char *parent_name, char *value, int parent_stmt, LY_STMT stmt)
+                         const char *parent_name, char **value, int parent_stmt, LY_STMT stmt)
 {
     int c;
     const char **str, ***p = NULL;
@@ -4782,7 +4782,8 @@
             for (c = 0; p[0][c + 1]; c++);
             str = p[1];
         }
-        str[c] = lydict_insert_zc(module->ctx, value);
+        str[c] = lydict_insert_zc(module->ctx, *value);
+        *value = NULL;
     }  else {
         str = lys_ext_complex_get_substmt(stmt, ext, &info);
         if (!str) {
@@ -4819,8 +4820,8 @@
             str = p[0];
         }
 
-        str[c] = lydict_insert_zc(module->ctx, value);
-        value = NULL;
+        str[c] = lydict_insert_zc(module->ctx, *value);
+        *value = NULL;
 
         if (c) {
             /* enlarge the array(s) */
@@ -4862,7 +4863,8 @@
     return EXIT_SUCCESS;
 
 error:
-    free(value);
+    free(*value);
+    *value = NULL;
     return EXIT_FAILURE;
 }
 
```
