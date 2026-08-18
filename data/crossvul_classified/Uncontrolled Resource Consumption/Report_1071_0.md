# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1071_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1071_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 6222-6262 of the vulnerable file.

}

static int
parse_char_class(Node** np, PToken* tok, UChar** src, UChar* end, ScanEnv* env)
{
  int r, neg, len, fetched, and_start;
  OnigCodePoint v, vs;
  UChar *p;
  Node* node;
  CClassNode *cc, *prev_cc;
  CClassNode work_cc;

  enum CCSTATE state;
  enum CCVALTYPE val_type, in_type;
  int val_israw, in_israw;

  *np = NULL_NODE;
  env->parse_depth++;
  if (env->parse_depth > ParseDepthLimit)
    return ONIGERR_PARSE_DEPTH_LIMIT_OVER;
  prev_cc = (CClassNode* )NULL;
  r = fetch_token_in_cc(tok, src, end, env);
  if (r == TK_CHAR && tok->u.c == '^' && tok->escaped == 0) {
    neg = 1;
    r = fetch_token_in_cc(tok, src, end, env);
  }
  else {
    neg = 0;
  }

  if (r < 0) return r;
  if (r == TK_CC_CLOSE) {
    if (! code_exist_check((OnigCodePoint )']',
                           *src, env->pattern_end, 1, env))
      return ONIGERR_EMPTY_CHAR_CLASS;

    CC_ESC_WARN(env, (UChar* )"]");
    r = tok->type = TK_CHAR;  /* allow []...] */
  }

  *np = node = node_new_cclass();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6239,6 +6239,7 @@
   env->parse_depth++;
   if (env->parse_depth > ParseDepthLimit)
     return ONIGERR_PARSE_DEPTH_LIMIT_OVER;
+
   prev_cc = (CClassNode* )NULL;
   r = fetch_token_in_cc(tok, src, end, env);
   if (r == TK_CHAR && tok->u.c == '^' && tok->escaped == 0) {
@@ -7820,13 +7821,17 @@
 parse_exp(Node** np, PToken* tok, int term, UChar** src, UChar* end,
           ScanEnv* env, int group_head)
 {
-  int r, len, group = 0;
+  int r, len, group;
   Node* qn;
   Node** tp;
-
+  unsigned int parse_depth;
+
+  group = 0;
   *np = NULL;
   if (tok->type == (enum TokenSyms )term)
     goto end_of_token;
+
+  parse_depth = env->parse_depth;
 
   switch (tok->type) {
   case TK_ALT:
@@ -8145,6 +8150,10 @@
       if (is_invalid_quantifier_target(*tp))
         return ONIGERR_TARGET_OF_REPEAT_OPERATOR_INVALID;
 
+      parse_depth++;
+      if (parse_depth > ParseDepthLimit)
+        return ONIGERR_PARSE_DEPTH_LIMIT_OVER;
+
       qn = node_new_quantifier(tok->u.repeat.lower, tok->u.repeat.upper,
                                r == TK_INTERVAL);
       CHECK_NULL_RETURN_MEMERR(qn);
```
