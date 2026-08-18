# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1359_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1359_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1155-1195 of the vulnerable file.

    return ret;
}

API struct lyd_node *
lyd_new(struct lyd_node *parent, const struct lys_module *module, const char *name)
{
    const struct lys_node *snode = NULL, *siblings;

    if ((!parent && !module) || !name) {
        LOGARG;
        return NULL;
    }

    siblings = lyd_new_find_schema(parent, module, 0);
    if (!siblings) {
        LOGARG;
        return NULL;
    }

    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_CONTAINER | LYS_LIST | LYS_NOTIF
                         | LYS_RPC | LYS_ACTION, &snode) || !snode) {
        LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
               name, lys_node_module(siblings)->name, siblings->name);
        return NULL;
    }

    return _lyd_new(parent, snode, 0);
}

static struct lyd_node *
lyd_create_leaf(const struct lys_node *schema, const char *val_str, int dflt)
{
    struct lyd_node_leaf_list *ret;

    ret = calloc(1, sizeof *ret);
    LY_CHECK_ERR_RETURN(!ret, LOGMEM(schema->module->ctx), NULL);

    ret->schema = (struct lys_node *)schema;
    ret->validity = ly_new_node_validity(schema);
    if (resolve_applies_when(schema, 0, NULL)) {
        ret->when_status = LYD_WHEN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1172,7 +1172,7 @@
     }
 
     if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_CONTAINER | LYS_LIST | LYS_NOTIF
-                         | LYS_RPC | LYS_ACTION, &snode) || !snode) {
+                         | LYS_RPC | LYS_ACTION, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -1265,7 +1265,7 @@
         return NULL;
     }
 
-    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_LEAFLIST | LYS_LEAF, &snode) || !snode) {
+    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_LEAFLIST | LYS_LEAF, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -1513,7 +1513,7 @@
         return NULL;
     }
 
-    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_ANYDATA, &snode) || !snode) {
+    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_ANYDATA, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -1538,7 +1538,7 @@
         return NULL;
     }
 
-    if (lys_getnext_data(module, schema, name, strlen(name), LYS_CONTAINER, &snode) || !snode) {
+    if (lys_getnext_data(module, schema, name, strlen(name), LYS_CONTAINER, 0, &snode) || !snode) {
         LOGERR(module->ctx, LY_EINVAL, "Failed to find \"%s\" as a container child of \"%s:%s\".",
                name, module->name, schema->name);
         return NULL;
@@ -1564,7 +1564,7 @@
     }
 
     if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_CONTAINER | LYS_LIST | LYS_NOTIF
-                         | LYS_RPC | LYS_ACTION, &snode) || !snode) {
+                         | LYS_RPC | LYS_ACTION, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -1589,7 +1589,7 @@
         return NULL;
     }
 
-    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_LEAFLIST | LYS_LEAF, &snode) || !snode) {
+    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_LEAFLIST | LYS_LEAF, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -1615,7 +1615,7 @@
         return NULL;
     }
 
-    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_ANYDATA, &snode) || !snode) {
+    if (lys_getnext_data(module, lys_parent(siblings), name, strlen(name), LYS_ANYDATA, 0, &snode) || !snode) {
         LOGERR(siblings->module->ctx, LY_EINVAL, "Failed to find \"%s\" as a sibling to \"%s:%s\".",
                name, lys_node_module(siblings)->name, siblings->name);
         return NULL;
@@ -5609,7 +5609,7 @@
                 }
                 /* we know its parent, so we can start with it */
                 lys_getnext_data(trg_mod, parent->schema, elem->schema->name, strlen(elem->schema->name),
-                                 elem->schema->nodetype, (const struct lys_node **)&schema);
+                                 elem->schema->nodetype, 0, (const struct lys_node **)&schema);
             } else {
                 /* we have to search in complete context */
                 schema = lyd_get_schema_inctx(elem, ctx);
```
