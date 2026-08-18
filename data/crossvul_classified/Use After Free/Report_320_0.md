# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 320_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `320_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 223-263 of the vulnerable file.

{
    unsigned nSyms = darray_size(expr->keysym_list.syms);

    darray_append(expr->keysym_list.symsMapIndex, nSyms);
    darray_append(expr->keysym_list.symsNumEntries, 1);
    darray_append(expr->keysym_list.syms, sym);

    return expr;
}

ExprDef *
ExprAppendMultiKeysymList(ExprDef *expr, ExprDef *append)
{
    unsigned nSyms = darray_size(expr->keysym_list.syms);
    unsigned numEntries = darray_size(append->keysym_list.syms);

    darray_append(expr->keysym_list.symsMapIndex, nSyms);
    darray_append(expr->keysym_list.symsNumEntries, numEntries);
    darray_concat(expr->keysym_list.syms, append->keysym_list.syms);

    FreeStmt((ParseCommon *) &append);

    return expr;
}

KeycodeDef *
KeycodeCreate(xkb_atom_t name, int64_t value)
{
    KeycodeDef *def = malloc(sizeof(*def));
    if (!def)
        return NULL;

    def->common.type = STMT_KEYCODE;
    def->common.next = NULL;
    def->name = name;
    def->value = value;

    return def;
}

KeyAliasDef *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -240,7 +240,7 @@
     darray_append(expr->keysym_list.symsNumEntries, numEntries);
     darray_concat(expr->keysym_list.syms, append->keysym_list.syms);
 
-    FreeStmt((ParseCommon *) &append);
+    FreeStmt((ParseCommon *) append);
 
     return expr;
 }
```
