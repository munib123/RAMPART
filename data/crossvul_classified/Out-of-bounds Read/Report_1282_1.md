# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1282_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1282_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1483-1523 of the vulnerable file.

static expr_ty
ast_for_atom(struct compiling *c, const node *n)
{
    /* atom: '(' [yield_expr|testlist_comp] ')' | '[' [listmaker] ']'
       | '{' [dictmaker] '}' | '`' testlist '`' | NAME | NUMBER | STRING+
    */
    node *ch = CHILD(n, 0);

    switch (TYPE(ch)) {
    case NAME: {
        /* All names start in Load context, but may later be
           changed. */
        PyObject *name = NEW_IDENTIFIER(ch);
        if (!name)
            return NULL;
        return Name(name, Load, LINENO(n), n->n_col_offset, c->c_arena);
    }
    case STRING: {
        PyObject *kind, *str = parsestrplus(c, n);
        const char *raw, *s = STR(CHILD(n, 0));
        int quote = Py_CHARMASK(*s);
        /* currently Python allows up to 2 string modifiers */
        char *ch, s_kind[3] = {0, 0, 0};
        ch = s_kind;
        raw = s;
        while (*raw && *raw != '\'' && *raw != '"') {
            *ch++ = *raw++;
        }
        kind = PyUnicode_FromString(s_kind);
        if (!kind) {
            return NULL;
        }
        if (!str) {
#ifdef Py_USING_UNICODE
            if (PyErr_ExceptionMatches(PyExc_UnicodeError)){
                PyObject *type, *value, *tback, *errstr;
                PyErr_Fetch(&type, &value, &tback);
                errstr = PyObject_Str(value);
                if (errstr) {
                    char *s = "";
                    char buf[128];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1500,7 +1500,6 @@
     case STRING: {
         PyObject *kind, *str = parsestrplus(c, n);
         const char *raw, *s = STR(CHILD(n, 0));
-        int quote = Py_CHARMASK(*s);
         /* currently Python allows up to 2 string modifiers */
         char *ch, s_kind[3] = {0, 0, 0};
         ch = s_kind;
@@ -1519,7 +1518,7 @@
                 PyErr_Fetch(&type, &value, &tback);
                 errstr = PyObject_Str(value);
                 if (errstr) {
-                    char *s = "";
+                    const char *s = "";
                     char buf[128];
                     s = _PyUnicode_AsString(errstr);
                     PyOS_snprintf(buf, sizeof(buf), "(unicode error) %s", s);
@@ -2190,7 +2189,7 @@
                 keyword_ty kw;
                 identifier key;
                 int k;
-                char *tmp;
+                const char *tmp;
 
                 /* CHILD(ch, 0) is test, but must be an identifier? */
                 e = ast_for_expr(c, CHILD(ch, 0));
```
