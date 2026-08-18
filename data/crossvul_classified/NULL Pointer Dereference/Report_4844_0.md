# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4844_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4844_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 173-213 of the vulnerable file.

/* The state buf must be large enough to hold one state per character in the main buffer.
 */
#define YY_STATE_BUF_SIZE   ((YY_BUF_SIZE + 2) * sizeof(yy_state_type))

#ifndef YY_TYPEDEF_YY_BUFFER_STATE
#define YY_TYPEDEF_YY_BUFFER_STATE
typedef struct yy_buffer_state *YY_BUFFER_STATE;
#endif

#ifndef YY_TYPEDEF_YY_SIZE_T
#define YY_TYPEDEF_YY_SIZE_T
typedef size_t yy_size_t;
#endif

#define EOB_ACT_CONTINUE_SCAN 0
#define EOB_ACT_END_OF_FILE 1
#define EOB_ACT_LAST_MATCH 2

    /* Note: We specifically omit the test for yy_rule_can_match_eol because it requires
     *       access to the local variable yy_act. Since yyless() is a macro, it would break
     *       existing scanners that call yyless() from OUTSIDE re_yylex. 
     *       One obvious solution it to make yy_act a global. I tried that, and saw
     *       a 5% performance hit in a non-yylineno scanner, because yy_act is
     *       normally declared as a register variable-- so it is not worth it.
     */
    #define  YY_LESS_LINENO(n) \
            do { \
                int yyl;\
                for ( yyl = n; yyl < yyleng; ++yyl )\
                    if ( yytext[yyl] == '\n' )\
                        --yylineno;\
            }while(0)
    #define YY_LINENO_REWIND_TO(dst) \
            do {\
                const char *p;\
                for ( p = yy_cp-1; p >= (dst); --p)\
                    if ( *p == '\n' )\
                        --yylineno;\
            }while(0)
    
/* Return all but the first "n" matched characters back to the input stream. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -190,7 +190,7 @@
 
     /* Note: We specifically omit the test for yy_rule_can_match_eol because it requires
      *       access to the local variable yy_act. Since yyless() is a macro, it would break
-     *       existing scanners that call yyless() from OUTSIDE re_yylex. 
+     *       existing scanners that call yyless() from OUTSIDE re_yylex.
      *       One obvious solution it to make yy_act a global. I tried that, and saw
      *       a 5% performance hit in a non-yylineno scanner, because yy_act is
      *       normally declared as a register variable-- so it is not worth it.
@@ -266,7 +266,7 @@
 
     int yy_bs_lineno; /**< The line count. */
     int yy_bs_column; /**< The column count. */
-    
+
 	/* Whether to try to fill the input buffer when we reach the
 	 * end of it.
 	 */
@@ -906,7 +906,7 @@
 			yy_size_t yyl;
 			for ( yyl = 0; yyl < yyleng; ++yyl )
 				if ( yytext[yyl] == '\n' )
-					   
+					
     do{ yylineno++;
         yycolumn=0;
     }while(0)
@@ -1125,7 +1125,7 @@
   }
   else
   {
-    yyerror(yyscanner, lex_env, "unexpected end of buffer");
+    yyerror(yyscanner, lex_env, "illegal escape sequence");
     yyterminate();
   }
 }
@@ -1180,7 +1180,7 @@
   {
     if (!read_escaped_char(yyscanner, &end))
     {
-      yyerror(yyscanner, lex_env, "unexpected end of buffer");
+      yyerror(yyscanner, lex_env, "illegal escape sequence");
       yyterminate();
     }
   }
@@ -1292,7 +1292,7 @@
   }
   else
   {
-    yyerror(yyscanner, lex_env, "unexpected end of buffer");
+    yyerror(yyscanner, lex_env, "illegal escape sequence");
     yyterminate();
   }
 }
@@ -1763,7 +1763,7 @@
 	yyg->yy_hold_char = *++yyg->yy_c_buf_p;
 
 	if ( c == '\n' )
-		   
+		
     do{ yylineno++;
         yycolumn=0;
     }while(0)
@@ -2018,9 +2018,9 @@
 								, yyscanner);
 		if ( ! yyg->yy_buffer_stack )
 			YY_FATAL_ERROR( "out of dynamic memory in re_yyensure_buffer_stack()" );
-								  
+
 		memset(yyg->yy_buffer_stack, 0, num_to_alloc * sizeof(struct yy_buffer_state*));
-				
+
 		yyg->yy_buffer_stack_max = num_to_alloc;
 		yyg->yy_buffer_stack_top = 0;
 		return;
@@ -2049,7 +2049,7 @@
  * @param base the character buffer
  * @param size the size in bytes of the character buffer
  * @param yyscanner The scanner object.
- * @return the newly allocated buffer state object. 
+ * @return the newly allocated buffer state object.
  */
 YY_BUFFER_STATE re_yy_scan_buffer  (char * base, yy_size_t  size , yyscan_t yyscanner)
 {
@@ -2177,7 +2177,7 @@
 int re_yyget_lineno  (yyscan_t yyscanner)
 {
     struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
-    
+
         if (! YY_CURRENT_BUFFER)
             return 0;
     
@@ -2190,7 +2190,7 @@
 int re_yyget_column  (yyscan_t yyscanner)
 {
     struct yyguts_t * yyg = (struct yyguts_t*)yyscanner;
-    
+
         if (! YY_CURRENT_BUFFER)
             return 0;
     
@@ -2365,20 +2365,20 @@
         errno = EINVAL;
         return 1;
     }
-	
+
     *ptr_yy_globals = (yyscan_t) re_yyalloc ( sizeof( struct yyguts_t ), &dummy_yyguts );
-	
+
     if (*ptr_yy_globals == NULL){
         errno = ENOMEM;
         return 1;
     }
-    
+
     /* By setting to 0xAA, we expose bugs in
     yy_init_globals. Leave at 0x00 for releases. */
     memset(*ptr_yy_globals,0x00,sizeof(struct yyguts_t));
-    
+
     re_yyset_extra (yy_user_defined, *ptr_yy_globals);
-    
+
     return yy_init_globals ( *ptr_yy_globals );
 }
 
@@ -2568,19 +2568,19 @@
   text[0] = '\\';
   text[1] = RE_YY_INPUT(yyscanner);
 
-  if (text[1] == EOF)
+  if (text[1] == EOF || text[1] == 0)
     return 0;
 
   if (text[1] == 'x')
   {
     text[2] = RE_YY_INPUT(yyscanner);
 
-    if (text[2] == EOF)
+    if (!isxdigit(text[2]))
       return 0;
 
     text[3] = RE_YY_INPUT(yyscanner);
 
-    if (text[3] == EOF)
+    if (!isxdigit(text[3]))
       return 0;
   }
 
```
