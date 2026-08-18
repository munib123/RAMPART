# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1359_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1359_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3924-3964 of the vulnerable file.

    const char *path_key_expr, *source, *sour_pref, *dest, *dest_pref;
    int pke_len, sour_len, sour_pref_len, dest_len, dest_pref_len, pke_parsed, parsed = 0;
    int has_predicate, dest_parent_times, i, rc;
    struct ly_ctx *ctx = context_node->module->ctx;

    do {
        if ((i = parse_path_predicate(path, &sour_pref, &sour_pref_len, &source, &sour_len, &path_key_expr,
                                      &pke_len, &has_predicate)) < 1) {
            LOGVAL(ctx, LYE_INCHAR, LY_VLOG_LYS, parent, path[-i], path-i);
            return -parsed+i;
        }
        parsed += i;
        path += i;

        /* source (must be leaf) */
        if (sour_pref) {
            trg_mod = lyp_get_module(lys_node_module(parent), NULL, 0, sour_pref, sour_pref_len, 0);
        } else {
            trg_mod = lys_node_module(parent);
        }
        rc = lys_getnext_data(trg_mod, context_node, source, sour_len, LYS_LEAF | LYS_LEAFLIST, &src_node);
        if (rc) {
            LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path-parsed);
            return 0;
        }

        /* destination */
        dest_parent_times = 0;
        pke_parsed = 0;
        if ((i = parse_path_key_expr(path_key_expr, &dest_pref, &dest_pref_len, &dest, &dest_len,
                                     &dest_parent_times)) < 1) {
            LOGVAL(ctx, LYE_INCHAR, LY_VLOG_LYS, parent, path_key_expr[-i], path_key_expr-i);
            return -parsed;
        }
        pke_parsed += i;

        for (i = 0, dst_node = parent; i < dest_parent_times; ++i) {
            if (!dst_node) {
                /* we went too much into parents, there is no parent anymore */
                LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path_key_expr);
                return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3941,7 +3941,8 @@
         } else {
             trg_mod = lys_node_module(parent);
         }
-        rc = lys_getnext_data(trg_mod, context_node, source, sour_len, LYS_LEAF | LYS_LEAFLIST, &src_node);
+        rc = lys_getnext_data(trg_mod, context_node, source, sour_len, LYS_LEAF | LYS_LEAFLIST, LYS_GETNEXT_NOSTATECHECK,
+                              &src_node);
         if (rc) {
             LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path-parsed);
             return 0;
@@ -3984,7 +3985,8 @@
             } else {
                 trg_mod = lys_node_module(parent);
             }
-            rc = lys_getnext_data(trg_mod, dst_node, dest, dest_len, LYS_CONTAINER | LYS_LIST | LYS_LEAF, &dst_node);
+            rc = lys_getnext_data(trg_mod, dst_node, dest, dest_len, LYS_CONTAINER | LYS_LIST | LYS_LEAF,
+                                  LYS_GETNEXT_NOSTATECHECK, &dst_node);
             if (rc) {
                 LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path_key_expr);
                 return 0;
@@ -6065,7 +6067,7 @@
         }
 
         rc = lys_getnext_data(lys_node_module((struct lys_node *)list), (struct lys_node *)list, keys_str, len, LYS_LEAF,
-                              (const struct lys_node **)&list->keys[i]);
+                              LYS_GETNEXT_NOSTATECHECK, (const struct lys_node **)&list->keys[i]);
         if (rc) {
             LOGVAL(ctx, LYE_INRESOLV, LY_VLOG_LYS, list, "list key", keys_str);
             return EXIT_FAILURE;
```
