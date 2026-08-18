# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3885_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3885_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1191-1231 of the vulnerable file.

#define grok_bslash_N(a,b,c,d,e,f,g)	S_grok_bslash_N(aTHX_ a,b,c,d,e,f,g)
#define handle_named_backref(a,b,c,d)	S_handle_named_backref(aTHX_ a,b,c,d)
#define handle_possible_posix(a,b,c,d,e)	S_handle_possible_posix(aTHX_ a,b,c,d,e)
#define handle_regex_sets(a,b,c,d,e)	S_handle_regex_sets(aTHX_ a,b,c,d,e)
#define handle_user_defined_property(a,b,c,d,e,f,g,h,i,j)	Perl_handle_user_defined_property(aTHX_ a,b,c,d,e,f,g,h,i,j)
#define invlist_contents(a,b)	S_invlist_contents(aTHX_ a,b)
#define invlist_highest		S_invlist_highest
#define invlist_is_iterating	S_invlist_is_iterating
#define invlist_iterfinish	S_invlist_iterfinish
#define invlist_iterinit	S_invlist_iterinit
#define invlist_iternext	S_invlist_iternext
#define is_ssc_worth_it		S_is_ssc_worth_it
#define join_exact(a,b,c,d,e,f,g)	S_join_exact(aTHX_ a,b,c,d,e,f,g)
#define make_trie(a,b,c,d,e,f,g,h)	S_make_trie(aTHX_ a,b,c,d,e,f,g,h)
#define new_regcurly		S_new_regcurly
#define nextchar(a)		S_nextchar(aTHX_ a)
#define output_posix_warnings(a,b)	S_output_posix_warnings(aTHX_ a,b)
#define parse_lparen_question_flags(a)	S_parse_lparen_question_flags(aTHX_ a)
#define parse_uniprop_string(a,b,c,d,e,f,g,h,i)	Perl_parse_uniprop_string(aTHX_ a,b,c,d,e,f,g,h,i)
#define populate_ANYOF_from_invlist(a,b)	S_populate_ANYOF_from_invlist(aTHX_ a,b)
#define reg(a,b,c,d)		S_reg(aTHX_ a,b,c,d)
#define reg2Lanode(a,b,c,d)	S_reg2Lanode(aTHX_ a,b,c,d)
#define reg_node(a,b)		S_reg_node(aTHX_ a,b)
#define reg_scan_name(a,b)	S_reg_scan_name(aTHX_ a,b)
#define reg_skipcomment		S_reg_skipcomment
#define reganode(a,b,c)		S_reganode(aTHX_ a,b,c)
#define regatom(a,b,c)		S_regatom(aTHX_ a,b,c)
#define regbranch(a,b,c,d)	S_regbranch(aTHX_ a,b,c,d)
#define regclass(a,b,c,d,e,f,g,h,i)	S_regclass(aTHX_ a,b,c,d,e,f,g,h,i)
#define regex_set_precedence	S_regex_set_precedence
#define reginsert(a,b,c,d)	S_reginsert(aTHX_ a,b,c,d)
#define regnode_guts(a,b,c,d)	S_regnode_guts(aTHX_ a,b,c,d)
#define regpiece(a,b,c)		S_regpiece(aTHX_ a,b,c)
#define regtail(a,b,c,d)	S_regtail(aTHX_ a,b,c,d)
#define scan_commit(a,b,c,d)	S_scan_commit(aTHX_ a,b,c,d)
#define set_ANYOF_arg(a,b,c,d,e)	S_set_ANYOF_arg(aTHX_ a,b,c,d,e)
#define set_regex_pv(a,b)	S_set_regex_pv(aTHX_ a,b)
#define skip_to_be_ignored_text(a,b,c)	S_skip_to_be_ignored_text(aTHX_ a,b,c)
#define ssc_add_range(a,b,c)	S_ssc_add_range(aTHX_ a,b,c)
#define ssc_and(a,b,c)		S_ssc_and(aTHX_ a,b,c)
#define ssc_anything(a)		S_ssc_anything(aTHX_ a)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1208,6 +1208,7 @@
 #define parse_lparen_question_flags(a)	S_parse_lparen_question_flags(aTHX_ a)
 #define parse_uniprop_string(a,b,c,d,e,f,g,h,i)	Perl_parse_uniprop_string(aTHX_ a,b,c,d,e,f,g,h,i)
 #define populate_ANYOF_from_invlist(a,b)	S_populate_ANYOF_from_invlist(aTHX_ a,b)
+#define rck_elide_nothing(a)	S_rck_elide_nothing(aTHX_ a)
 #define reg(a,b,c,d)		S_reg(aTHX_ a,b,c,d)
 #define reg2Lanode(a,b,c,d)	S_reg2Lanode(aTHX_ a,b,c,d)
 #define reg_node(a,b)		S_reg_node(aTHX_ a,b)
```
