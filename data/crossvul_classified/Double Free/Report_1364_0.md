# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1364_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1364_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 9106-9133 of the vulnerable file.

                  yystos[*yyssp], yyvsp, yylsp, scanner, param);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}



void
yyerror(YYLTYPE *yylloc, void *scanner, struct yang_parameter *param, ...)
{
  free(*param->value);
  if (yylloc->first_line != -1) {
    if (*param->data_node && (*param->data_node) == (*param->actual_node)) {
      LOGVAL(param->module->ctx, LYE_INSTMT, LY_VLOG_LYS, *param->data_node, yyget_text(scanner));
    } else {
      LOGVAL(param->module->ctx, LYE_INSTMT, LY_VLOG_NONE, NULL, yyget_text(scanner));
    }
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9123,6 +9123,7 @@
 yyerror(YYLTYPE *yylloc, void *scanner, struct yang_parameter *param, ...)
 {
   free(*param->value);
+  *param->value = NULL;
   if (yylloc->first_line != -1) {
     if (*param->data_node && (*param->data_node) == (*param->actual_node)) {
       LOGVAL(param->module->ctx, LYE_INSTMT, LY_VLOG_LYS, *param->data_node, yyget_text(scanner));
```
