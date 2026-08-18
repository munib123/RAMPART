# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 317_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `317_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.

    STMT_KEYCODE,
    STMT_ALIAS,
    STMT_EXPR,
    STMT_VAR,
    STMT_TYPE,
    STMT_INTERP,
    STMT_VMOD,
    STMT_SYMBOLS,
    STMT_MODMAP,
    STMT_GROUP_COMPAT,
    STMT_LED_MAP,
    STMT_LED_NAME,

    _STMT_NUM_VALUES
};

enum expr_value_type {
    EXPR_TYPE_UNKNOWN = 0,
    EXPR_TYPE_BOOLEAN,
    EXPR_TYPE_INT,
    EXPR_TYPE_STRING,
    EXPR_TYPE_ACTION,
    EXPR_TYPE_KEYNAME,
    EXPR_TYPE_SYMBOLS,

    _EXPR_TYPE_NUM_VALUES
};

enum expr_op_type {
    EXPR_VALUE,
    EXPR_IDENT,
    EXPR_ACTION_DECL,
    EXPR_FIELD_REF,
    EXPR_ARRAY_REF,
    EXPR_KEYSYM_LIST,
    EXPR_ACTION_LIST,
    EXPR_ADD,
    EXPR_SUBTRACT,
    EXPR_MULTIPLY,
    EXPR_DIVIDE,
    EXPR_ASSIGN,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,7 @@
     EXPR_TYPE_UNKNOWN = 0,
     EXPR_TYPE_BOOLEAN,
     EXPR_TYPE_INT,
+    EXPR_TYPE_FLOAT,
     EXPR_TYPE_STRING,
     EXPR_TYPE_ACTION,
     EXPR_TYPE_KEYNAME,
@@ -188,6 +189,12 @@
 
 typedef struct {
     ExprCommon expr;
+    /* We don't support floats, but we still represnt them in the AST, in
+     * order to provide proper error messages. */
+} ExprFloat;
+
+typedef struct {
+    ExprCommon expr;
     xkb_atom_t key_name;
 } ExprKeyName;
 
```
