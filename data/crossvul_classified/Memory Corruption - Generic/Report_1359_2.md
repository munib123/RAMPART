# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1359_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1359_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 468-508 of the vulnerable file.

 * @param[in] mod_name_len Module name length.
 * @param[in] name Node name, mandatory.
 * @param[in] nam_len Node name length.
 * @param[in] type ORed desired type of the node. 0 means any type.
 *                 Does not return groupings, uses, and augments (but can return augment nodes).
 * @param[out] ret Pointer to the node of the desired type. Can be NULL.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on forward reference.
 */
int lys_get_sibling(const struct lys_node *siblings, const char *mod_name, int mod_name_len, const char *name,
                    int nam_len, LYS_NODE type, const struct lys_node **ret);

/**
 * @brief Find a specific node that can only appear in the data. Does not log.
 *
 * @param[in] mod Main module with the node. Must be set if \p parent == NULL (top-level node).
 * @param[in] parent Parent of the node. Must be set if \p mod == NULL (nested node).
 * @param[in] name Node name.
 * @param[in] nam_len Node \p name length.
 * @param[in] type ORed desired type of the node. 0 means any (data node) type.
 * @param[out] ret Pointer to the node of the desired type. Can be NULL.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on fail.
 */
int lys_getnext_data(const struct lys_module *mod, const struct lys_node *parent, const char *name, int nam_len,
                     LYS_NODE type, const struct lys_node **ret);

int lyd_get_unique_default(const char* unique_expr, struct lyd_node *list, const char **dflt);

int lyd_build_relative_data_path(const struct lys_module *module, const struct lyd_node *node, const char *schema_id,
                                 char *buf);

void lyd_free_value(lyd_val value, LY_DATA_TYPE value_type, uint8_t value_flags, struct lys_type *type, lyd_val *old_val,
                    LY_DATA_TYPE *old_val_type, uint8_t *old_val_flags);

int lyd_list_equal(struct lyd_node *node1, struct lyd_node *node2, int with_defaults);

int lys_make_implemented_r(struct lys_module *module, struct unres_schema *unres);

/**
 * @brief Check for (validate) mandatory nodes of a data tree. Checks recursively whole data tree. Requires all when
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -485,12 +485,13 @@
  * @param[in] name Node name.
  * @param[in] nam_len Node \p name length.
  * @param[in] type ORed desired type of the node. 0 means any (data node) type.
+ * @param[in] getnext_opts lys_getnext() options to use.
  * @param[out] ret Pointer to the node of the desired type. Can be NULL.
  *
  * @return EXIT_SUCCESS on success, EXIT_FAILURE on fail.
  */
 int lys_getnext_data(const struct lys_module *mod, const struct lys_node *parent, const char *name, int nam_len,
-                     LYS_NODE type, const struct lys_node **ret);
+                     LYS_NODE type, int getnext_opts, const struct lys_node **ret);
 
 int lyd_get_unique_default(const char* unique_expr, struct lyd_node *list, const char **dflt);
 
```
