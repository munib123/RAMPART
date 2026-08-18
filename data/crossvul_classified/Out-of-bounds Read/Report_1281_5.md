# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1281_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1281_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 29-69 of the vulnerable file.


typedef enum _unaryop { Invert=1, Not=2, UAdd=3, USub=4 } unaryop_ty;

typedef enum _cmpop { Eq=1, NotEq=2, Lt=3, LtE=4, Gt=5, GtE=6, Is=7, IsNot=8,
                      In=9, NotIn=10 } cmpop_ty;

typedef struct _comprehension *comprehension_ty;

typedef struct _excepthandler *excepthandler_ty;

typedef struct _arguments *arguments_ty;

typedef struct _arg *arg_ty;

typedef struct _keyword *keyword_ty;

typedef struct _alias *alias_ty;

typedef struct _withitem *withitem_ty;


enum _mod_kind {Module_kind=1, Interactive_kind=2, Expression_kind=3,
                 Suite_kind=4};
struct _mod {
    enum _mod_kind kind;
    union {
        struct {
            asdl_seq *body;
        } Module;

        struct {
            asdl_seq *body;
        } Interactive;

        struct {
            expr_ty body;
        } Expression;

        struct {
            asdl_seq *body;
        } Suite;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,14 +46,17 @@
 
 typedef struct _withitem *withitem_ty;
 
+typedef struct _type_ignore *type_ignore_ty;
+
 
 enum _mod_kind {Module_kind=1, Interactive_kind=2, Expression_kind=3,
-                 Suite_kind=4};
+                 FunctionType_kind=4, Suite_kind=5};
 struct _mod {
     enum _mod_kind kind;
     union {
         struct {
             asdl_seq *body;
+            asdl_seq *type_ignores;
         } Module;
 
         struct {
@@ -63,6 +66,11 @@
         struct {
             expr_ty body;
         } Expression;
+
+        struct {
+            asdl_seq *argtypes;
+            expr_ty returns;
+        } FunctionType;
 
         struct {
             asdl_seq *body;
@@ -88,6 +96,7 @@
             asdl_seq *body;
             asdl_seq *decorator_list;
             expr_ty returns;
+            string type_comment;
         } FunctionDef;
 
         struct {
@@ -96,6 +105,7 @@
             asdl_seq *body;
             asdl_seq *decorator_list;
             expr_ty returns;
+            string type_comment;
         } AsyncFunctionDef;
 
         struct {
@@ -117,6 +127,7 @@
         struct {
             asdl_seq *targets;
             expr_ty value;
+            string type_comment;
         } Assign;
 
         struct {
@@ -137,6 +148,7 @@
             expr_ty iter;
             asdl_seq *body;
             asdl_seq *orelse;
+            string type_comment;
         } For;
 
         struct {
@@ -144,6 +156,7 @@
             expr_ty iter;
             asdl_seq *body;
             asdl_seq *orelse;
+            string type_comment;
         } AsyncFor;
 
         struct {
@@ -161,11 +174,13 @@
         struct {
             asdl_seq *items;
             asdl_seq *body;
+            string type_comment;
         } With;
 
         struct {
             asdl_seq *items;
             asdl_seq *body;
+            string type_comment;
         } AsyncWith;
 
         struct {
@@ -421,6 +436,7 @@
 struct _arg {
     identifier arg;
     expr_ty annotation;
+    string type_comment;
     int lineno;
     int col_offset;
     int end_lineno;
@@ -442,26 +458,40 @@
     expr_ty optional_vars;
 };
 
+enum _type_ignore_kind {TypeIgnore_kind=1};
+struct _type_ignore {
+    enum _type_ignore_kind kind;
+    union {
+        struct {
+            int lineno;
+        } TypeIgnore;
+
+    } v;
+};
+
 
 // Note: these macros affect function definitions, not only call sites.
-#define Module(a0, a1) _Py_Module(a0, a1)
-mod_ty _Py_Module(asdl_seq * body, PyArena *arena);
+#define Module(a0, a1, a2) _Py_Module(a0, a1, a2)
+mod_ty _Py_Module(asdl_seq * body, asdl_seq * type_ignores, PyArena *arena);
 #define Interactive(a0, a1) _Py_Interactive(a0, a1)
 mod_ty _Py_Interactive(asdl_seq * body, PyArena *arena);
 #define Expression(a0, a1) _Py_Expression(a0, a1)
 mod_ty _Py_Expression(expr_ty body, PyArena *arena);
+#define FunctionType(a0, a1, a2) _Py_FunctionType(a0, a1, a2)
+mod_ty _Py_FunctionType(asdl_seq * argtypes, expr_ty returns, PyArena *arena);
 #define Suite(a0, a1) _Py_Suite(a0, a1)
 mod_ty _Py_Suite(asdl_seq * body, PyArena *arena);
-#define FunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) _Py_FunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
+#define FunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) _Py_FunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
 stmt_ty _Py_FunctionDef(identifier name, arguments_ty args, asdl_seq * body,
-                        asdl_seq * decorator_list, expr_ty returns, int lineno,
-                        int col_offset, int end_lineno, int end_col_offset,
-                        PyArena *arena);
-#define AsyncFunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) _Py_AsyncFunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
+                        asdl_seq * decorator_list, expr_ty returns, string
+                        type_comment, int lineno, int col_offset, int
+                        end_lineno, int end_col_offset, PyArena *arena);
+#define AsyncFunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) _Py_AsyncFunctionDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
 stmt_ty _Py_AsyncFunctionDef(identifier name, arguments_ty args, asdl_seq *
                              body, asdl_seq * decorator_list, expr_ty returns,
-                             int lineno, int col_offset, int end_lineno, int
-                             end_col_offset, PyArena *arena);
+                             string type_comment, int lineno, int col_offset,
+                             int end_lineno, int end_col_offset, PyArena
+                             *arena);
 #define ClassDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) _Py_ClassDef(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
 stmt_ty _Py_ClassDef(identifier name, asdl_seq * bases, asdl_seq * keywords,
                      asdl_seq * body, asdl_seq * decorator_list, int lineno,
@@ -473,10 +503,10 @@
 #define Delete(a0, a1, a2, a3, a4, a5) _Py_Delete(a0, a1, a2, a3, a4, a5)
 stmt_ty _Py_Delete(asdl_seq * targets, int lineno, int col_offset, int
                    end_lineno, int end_col_offset, PyArena *arena);
-#define Assign(a0, a1, a2, a3, a4, a5, a6) _Py_Assign(a0, a1, a2, a3, a4, a5, a6)
-stmt_ty _Py_Assign(asdl_seq * targets, expr_ty value, int lineno, int
-                   col_offset, int end_lineno, int end_col_offset, PyArena
-                   *arena);
+#define Assign(a0, a1, a2, a3, a4, a5, a6, a7) _Py_Assign(a0, a1, a2, a3, a4, a5, a6, a7)
+stmt_ty _Py_Assign(asdl_seq * targets, expr_ty value, string type_comment, int
+                   lineno, int col_offset, int end_lineno, int end_col_offset,
+                   PyArena *arena);
 #define AugAssign(a0, a1, a2, a3, a4, a5, a6, a7) _Py_AugAssign(a0, a1, a2, a3, a4, a5, a6, a7)
 stmt_ty _Py_AugAssign(expr_ty target, operator_ty op, expr_ty value, int
                       lineno, int col_offset, int end_lineno, int
@@ -485,14 +515,14 @@
 stmt_ty _Py_AnnAssign(expr_ty target, expr_ty annotation, expr_ty value, int
                       simple, int lineno, int col_offset, int end_lineno, int
                       end_col_offset, PyArena *arena);
-#define For(a0, a1, a2, a3, a4, a5, a6, a7, a8) _Py_For(a0, a1, a2, a3, a4, a5, a6, a7, a8)
+#define For(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) _Py_For(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
 stmt_ty _Py_For(expr_ty target, expr_ty iter, asdl_seq * body, asdl_seq *
-                orelse, int lineno, int col_offset, int end_lineno, int
-                end_col_offset, PyArena *arena);
-#define AsyncFor(a0, a1, a2, a3, a4, a5, a6, a7, a8) _Py_AsyncFor(a0, a1, a2, a3, a4, a5, a6, a7, a8)
+                orelse, string type_comment, int lineno, int col_offset, int
+                end_lineno, int end_col_offset, PyArena *arena);
+#define AsyncFor(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) _Py_AsyncFor(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
 stmt_ty _Py_AsyncFor(expr_ty target, expr_ty iter, asdl_seq * body, asdl_seq *
-                     orelse, int lineno, int col_offset, int end_lineno, int
-                     end_col_offset, PyArena *arena);
+                     orelse, string type_comment, int lineno, int col_offset,
+                     int end_lineno, int end_col_offset, PyArena *arena);
 #define While(a0, a1, a2, a3, a4, a5, a6, a7) _Py_While(a0, a1, a2, a3, a4, a5, a6, a7)
 stmt_ty _Py_While(expr_ty test, asdl_seq * body, asdl_seq * orelse, int lineno,
                   int col_offset, int end_lineno, int end_col_offset, PyArena
@@ -501,13 +531,14 @@
 stmt_ty _Py_If(expr_ty test, asdl_seq * body, asdl_seq * orelse, int lineno,
                int col_offset, int end_lineno, int end_col_offset, PyArena
                *arena);
-#define With(a0, a1, a2, a3, a4, a5, a6) _Py_With(a0, a1, a2, a3, a4, a5, a6)
-stmt_ty _Py_With(asdl_seq * items, asdl_seq * body, int lineno, int col_offset,
-                 int end_lineno, int end_col_offset, PyArena *arena);
... (diff truncated)
```
