# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1359_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1359_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 196-236 of the vulnerable file.

            node_mod_name = lys_node_module(node)->name;
            if (!ly_strequal(node_mod_name, mod_name, 1) && (strncmp(node_mod_name, mod_name, mod_name_len) || node_mod_name[mod_name_len])) {
                continue;
            }

            /* direct name check */
            if (ly_strequal(node->name, name, 1) || (!strncmp(node->name, name, nam_len) && !node->name[nam_len])) {
                if (ret) {
                    *ret = node;
                }
                return EXIT_SUCCESS;
            }
        }
    }

    return EXIT_FAILURE;
}

int
lys_getnext_data(const struct lys_module *mod, const struct lys_node *parent, const char *name, int nam_len,
                 LYS_NODE type, const struct lys_node **ret)
{
    const struct lys_node *node;

    assert((mod || parent) && name);
    assert(!(type & (LYS_AUGMENT | LYS_USES | LYS_GROUPING | LYS_CHOICE | LYS_CASE | LYS_INPUT | LYS_OUTPUT)));

    if (!mod) {
        mod = lys_node_module(parent);
    }

    /* try to find the node */
    node = NULL;
    while ((node = lys_getnext(node, parent, mod, 0))) {
        if (!type || (node->nodetype & type)) {
            /* module check */
            if (lys_node_module(node) != lys_main_module(mod)) {
                continue;
            }

            /* direct name check */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,7 +213,7 @@
 
 int
 lys_getnext_data(const struct lys_module *mod, const struct lys_node *parent, const char *name, int nam_len,
-                 LYS_NODE type, const struct lys_node **ret)
+                 LYS_NODE type, int getnext_opts, const struct lys_node **ret)
 {
     const struct lys_node *node;
 
@@ -226,7 +226,7 @@
 
     /* try to find the node */
     node = NULL;
-    while ((node = lys_getnext(node, parent, mod, 0))) {
+    while ((node = lys_getnext(node, parent, mod, getnext_opts))) {
         if (!type || (node->nodetype & type)) {
             /* module check */
             if (lys_node_module(node) != lys_main_module(mod)) {
```
