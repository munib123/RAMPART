# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 317_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `317_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 85-125 of the vulnerable file.

}

#define EXPR_CREATE(type_, name_, op_, value_type_) \
    ExprDef *name_ = ExprCreate(op_, value_type_, sizeof(type_)); \
    if (!name_) \
        return NULL;

ExprDef *
ExprCreateString(xkb_atom_t str)
{
    EXPR_CREATE(ExprString, expr, EXPR_VALUE, EXPR_TYPE_STRING);
    expr->string.str = str;
    return expr;
}

ExprDef *
ExprCreateInteger(int ival)
{
    EXPR_CREATE(ExprInteger, expr, EXPR_VALUE, EXPR_TYPE_INT);
    expr->integer.ival = ival;
    return expr;
}

ExprDef *
ExprCreateBoolean(bool set)
{
    EXPR_CREATE(ExprBoolean, expr, EXPR_VALUE, EXPR_TYPE_BOOLEAN);
    expr->boolean.set = set;
    return expr;
}

ExprDef *
ExprCreateKeyName(xkb_atom_t key_name)
{
    EXPR_CREATE(ExprKeyName, expr, EXPR_VALUE, EXPR_TYPE_KEYNAME);
    expr->key_name.key_name = key_name;
    return expr;
}

ExprDef *
ExprCreateIdent(xkb_atom_t ident)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,6 +106,13 @@
 }
 
 ExprDef *
+ExprCreateFloat(void)
+{
+    EXPR_CREATE(ExprFloat, expr, EXPR_VALUE, EXPR_TYPE_FLOAT);
+    return expr;
+}
+
+ExprDef *
 ExprCreateBoolean(bool set)
 {
     EXPR_CREATE(ExprBoolean, expr, EXPR_VALUE, EXPR_TYPE_BOOLEAN);
@@ -783,6 +790,7 @@
     [EXPR_TYPE_UNKNOWN] = "unknown",
     [EXPR_TYPE_BOOLEAN] = "boolean",
     [EXPR_TYPE_INT] = "int",
+    [EXPR_TYPE_FLOAT] = "float",
     [EXPR_TYPE_STRING] = "string",
     [EXPR_TYPE_ACTION] = "action",
     [EXPR_TYPE_KEYNAME] = "keyname",
```
