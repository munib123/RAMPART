# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 3392_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3392_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 76-116 of the vulnerable file.


#include <yara/integers.h>
#include <yara/utils.h>
#include <yara/hex_lexer.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/error.h>


#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define YYERROR_VERBOSE

#define YYMALLOC yr_malloc
#define YYFREE yr_free

#define mark_as_not_fast_regexp() \
    ((RE_AST*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_REGEXP

#define ERROR_IF(x, error) \
    if (x) \
    { \
      lex_env->last_error_code = error; \
      YYABORT; \
    } \

#define DESTROY_NODE_IF(x, node) \
    if (x) \
    { \
      yr_re_node_destroy(node); \
    } \


#line 111 "hex_grammar.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,13 @@
 #define mark_as_not_fast_regexp() \
     ((RE_AST*) yyget_extra(yyscanner))->flags &= ~RE_FLAGS_FAST_REGEXP
 
+#define incr_ast_levels() \
+    if (((RE_AST*) yyget_extra(yyscanner))->levels++ > RE_MAX_AST_LEVELS) \
+    { \
+      lex_env->last_error_code = ERROR_INVALID_HEX_STRING; \
+      YYABORT; \
+    }
+
 #define ERROR_IF(x, error) \
     if (x) \
     { \
@@ -107,7 +114,7 @@
     } \
 
 
-#line 111 "hex_grammar.c" /* yacc.c:339  */
+#line 118 "hex_grammar.c" /* yacc.c:339  */
 
 # ifndef YY_NULLPTR
 #  if defined __cplusplus && 201103L <= __cplusplus
@@ -157,12 +164,12 @@
 
 union YYSTYPE
 {
-#line 78 "hex_grammar.y" /* yacc.c:355  */
+#line 85 "hex_grammar.y" /* yacc.c:355  */
 
   int64_t integer;
   RE_NODE *re_node;
 
-#line 166 "hex_grammar.c" /* yacc.c:355  */
+#line 173 "hex_grammar.c" /* yacc.c:355  */
 };
 
 typedef union YYSTYPE YYSTYPE;
@@ -178,7 +185,7 @@
 
 /* Copy the second part of user declarations.  */
 
-#line 182 "hex_grammar.c" /* yacc.c:358  */
+#line 189 "hex_grammar.c" /* yacc.c:358  */
 
 #ifdef short
 # undef short
@@ -476,9 +483,9 @@
   /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
 static const yytype_uint16 yyrline[] =
 {
-       0,   105,   105,   114,   118,   127,   189,   193,   206,   210,
-     219,   233,   232,   245,   268,   300,   322,   342,   346,   360,
-     368
+       0,   112,   112,   121,   125,   136,   200,   204,   219,   223,
+     232,   246,   245,   258,   281,   313,   335,   355,   359,   374,
+     382
 };
 #endif
 
@@ -1017,45 +1024,45 @@
   switch (yytype)
     {
           case 16: /* tokens  */
-#line 94 "hex_grammar.y" /* yacc.c:1257  */
+#line 101 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1023 "hex_grammar.c" /* yacc.c:1257  */
+#line 1030 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 17: /* token_sequence  */
-#line 95 "hex_grammar.y" /* yacc.c:1257  */
+#line 102 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1029 "hex_grammar.c" /* yacc.c:1257  */
+#line 1036 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 18: /* token_or_range  */
-#line 96 "hex_grammar.y" /* yacc.c:1257  */
+#line 103 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1035 "hex_grammar.c" /* yacc.c:1257  */
+#line 1042 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 19: /* token  */
-#line 97 "hex_grammar.y" /* yacc.c:1257  */
+#line 104 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1041 "hex_grammar.c" /* yacc.c:1257  */
+#line 1048 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 21: /* range  */
-#line 100 "hex_grammar.y" /* yacc.c:1257  */
+#line 107 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1047 "hex_grammar.c" /* yacc.c:1257  */
+#line 1054 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 22: /* alternatives  */
-#line 99 "hex_grammar.y" /* yacc.c:1257  */
+#line 106 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1053 "hex_grammar.c" /* yacc.c:1257  */
+#line 1060 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
     case 23: /* byte  */
-#line 98 "hex_grammar.y" /* yacc.c:1257  */
+#line 105 "hex_grammar.y" /* yacc.c:1257  */
       { yr_re_node_destroy(((*yyvaluep).re_node)); }
-#line 1059 "hex_grammar.c" /* yacc.c:1257  */
+#line 1066 "hex_grammar.c" /* yacc.c:1257  */
         break;
 
 
@@ -1321,25 +1328,27 @@
   switch (yyn)
     {
         case 2:
-#line 106 "hex_grammar.y" /* yacc.c:1646  */
+#line 113 "hex_grammar.y" /* yacc.c:1661  */
     {
         RE_AST* re_ast = yyget_extra(yyscanner);
         re_ast->root_node = (yyvsp[-1].re_node);
       }
-#line 1330 "hex_grammar.c" /* yacc.c:1646  */
+#line 1337 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 3:
-#line 115 "hex_grammar.y" /* yacc.c:1646  */
+#line 122 "hex_grammar.y" /* yacc.c:1661  */
     {
         (yyval.re_node) = (yyvsp[0].re_node);
       }
-#line 1338 "hex_grammar.c" /* yacc.c:1646  */
+#line 1345 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 4:
-#line 119 "hex_grammar.y" /* yacc.c:1646  */
-    {
+#line 126 "hex_grammar.y" /* yacc.c:1661  */
+    {
+        incr_ast_levels();
+
         (yyval.re_node) = yr_re_node_create(RE_NODE_CONCAT, (yyvsp[-1].re_node), (yyvsp[0].re_node));
 
         DESTROY_NODE_IF((yyval.re_node) == NULL, (yyvsp[-1].re_node));
@@ -1347,15 +1356,17 @@
 
         ERROR_IF((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
       }
-#line 1351 "hex_grammar.c" /* yacc.c:1646  */
+#line 1360 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 5:
-#line 128 "hex_grammar.y" /* yacc.c:1646  */
+#line 137 "hex_grammar.y" /* yacc.c:1661  */
     {
         RE_NODE* new_concat;
         RE_NODE* leftmost_concat = NULL;
         RE_NODE* leftmost_node = (yyvsp[-1].re_node);
+
+        incr_ast_levels();
 
         (yyval.re_node) = NULL;
 
@@ -1409,20 +1420,22 @@
 
         ERROR_IF((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
       }
-#line 1413 "hex_grammar.c" /* yacc.c:1646  */
+#line 1424 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 6:
-#line 190 "hex_grammar.y" /* yacc.c:1646  */
+#line 201 "hex_grammar.y" /* yacc.c:1661  */
     {
         (yyval.re_node) = (yyvsp[0].re_node);
       }
-#line 1421 "hex_grammar.c" /* yacc.c:1646  */
+#line 1432 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 7:
-#line 194 "hex_grammar.y" /* yacc.c:1646  */
-    {
+#line 205 "hex_grammar.y" /* yacc.c:1661  */
+    {
+        incr_ast_levels();
+
         (yyval.re_node) = yr_re_node_create(RE_NODE_CONCAT, (yyvsp[-1].re_node), (yyvsp[0].re_node));
 
         DESTROY_NODE_IF((yyval.re_node) == NULL, (yyvsp[-1].re_node));
@@ -1430,28 +1443,28 @@
 
         ERROR_IF((yyval.re_node) == NULL, ERROR_INSUFFICIENT_MEMORY);
       }
-#line 1434 "hex_grammar.c" /* yacc.c:1646  */
+#line 1447 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 8:
-#line 207 "hex_grammar.y" /* yacc.c:1646  */
+#line 220 "hex_grammar.y" /* yacc.c:1661  */
     {
         (yyval.re_node) = (yyvsp[0].re_node);
       }
-#line 1442 "hex_grammar.c" /* yacc.c:1646  */
+#line 1455 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 9:
-#line 211 "hex_grammar.y" /* yacc.c:1646  */
+#line 224 "hex_grammar.y" /* yacc.c:1661  */
     {
         (yyval.re_node) = (yyvsp[0].re_node);
         (yyval.re_node)->greedy = FALSE;
       }
-#line 1451 "hex_grammar.c" /* yacc.c:1646  */
+#line 1464 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 10:
-#line 220 "hex_grammar.y" /* yacc.c:1646  */
+#line 233 "hex_grammar.y" /* yacc.c:1661  */
     {
         lex_env->token_count++;
 
@@ -1464,28 +1477,28 @@
 
         (yyval.re_node) = (yyvsp[0].re_node);
       }
-#line 1468 "hex_grammar.c" /* yacc.c:1646  */
+#line 1481 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 11:
-#line 233 "hex_grammar.y" /* yacc.c:1646  */
+#line 246 "hex_grammar.y" /* yacc.c:1661  */
     {
         lex_env->inside_or++;
       }
-#line 1476 "hex_grammar.c" /* yacc.c:1646  */
+#line 1489 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 12:
-#line 237 "hex_grammar.y" /* yacc.c:1646  */
+#line 250 "hex_grammar.y" /* yacc.c:1661  */
     {
         (yyval.re_node) = (yyvsp[-1].re_node);
         lex_env->inside_or--;
       }
-#line 1485 "hex_grammar.c" /* yacc.c:1646  */
+#line 1498 "hex_grammar.c" /* yacc.c:1661  */
     break;
 
   case 13:
-#line 246 "hex_grammar.y" /* yacc.c:1646  */
+#line 259 "hex_grammar.y" /* yacc.c:1661  */
     {
         if ((yyvsp[-1].integer) <= 0)
         {
@@ -1508,11 +1521,11 @@
         (yyval.re_node)->start = (int) (yyvsp[-1].integer);
         (yyval.re_node)->end = (int) (yyvsp[-1].integer);
       }
... (diff truncated)
```
