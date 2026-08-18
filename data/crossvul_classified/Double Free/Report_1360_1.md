# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1360_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1360_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 157-197 of the vulnerable file.

int yang_read_augment(struct lys_module *module, struct lys_node *parent, struct lys_node_augment *aug, char *value);

void *yang_read_deviate(struct ly_ctx *ctx, struct lys_deviation *dev, LYS_DEVIATE_TYPE mod);

void *yang_read_deviate_unsupported(struct ly_ctx *ctx, struct lys_deviation *dev);

int yang_fill_unique(struct lys_module *module, struct lys_node_list *list, struct lys_unique *unique, char *value, struct unres_schema *unres);

int yang_fill_iffeature(struct lys_module *module, struct lys_iffeature *iffeature, void *parent,
                        char *value, struct unres_schema *unres, int parent_is_feature);

void yang_free_ext_data(struct yang_ext_substmt *substmt);

void *yang_read_ext(struct lys_module *module, void *actual, char *ext_name, char *ext_arg,
                    enum yytokentype actual_type, enum yytokentype backup_type, int is_ext_instance);

int yang_check_ext_instance(struct lys_module *module, struct lys_ext_instance ***ext, uint size,
                            void *parent, struct unres_schema *unres);

int yang_read_extcomplex_str(struct lys_module *module, struct lys_ext_instance_complex *ext, const char *arg_name,
                             const char *parent_name, char *value, int parent_stmt, LY_STMT stmt);

void **yang_getplace_for_extcomplex_struct(struct lys_ext_instance_complex *ext, int *index,
                                    char *parent_name, char *node_name, LY_STMT stmt);

int yang_extcomplex_node(struct lys_ext_instance_complex *ext, char *parent_name, char *node_name,
                         struct lys_node *node, LY_STMT stmt);

int yang_fill_extcomplex_flags(struct lys_ext_instance_complex *ext, char *parent_name, char *node_name,
                               LY_STMT stmt, uint16_t value, uint16_t mask);

int yang_fill_extcomplex_uint8(struct lys_ext_instance_complex *ext, char *parent_name, char *node_name,
                               LY_STMT stmt, uint8_t value);

int yang_parse_ext_substatement(struct lys_module *module, struct unres_schema *unres, const char *data,
                                char *ext_name, struct lys_ext_instance_complex *ext);

int yang_fill_extcomplex_module(struct ly_ctx *ctx, struct lys_ext_instance_complex *ext,
                                char *parent_name, char **values, int implemented);


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -174,7 +174,7 @@
                             void *parent, struct unres_schema *unres);
 
 int yang_read_extcomplex_str(struct lys_module *module, struct lys_ext_instance_complex *ext, const char *arg_name,
-                             const char *parent_name, char *value, int parent_stmt, LY_STMT stmt);
+                             const char *parent_name, char **value, int parent_stmt, LY_STMT stmt);
 
 void **yang_getplace_for_extcomplex_struct(struct lys_ext_instance_complex *ext, int *index,
                                     char *parent_name, char *node_name, LY_STMT stmt);
```
