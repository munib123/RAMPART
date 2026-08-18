# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4012_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4012_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 1222-1262 of the vulnerable file.

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
#define ssc_clear_locale	S_ssc_clear_locale
#define ssc_cp_and(a,b)		S_ssc_cp_and(aTHX_ a,b)
#define ssc_finalize(a,b)	S_ssc_finalize(aTHX_ a,b)
#define ssc_init(a,b)		S_ssc_init(aTHX_ a,b)
#define ssc_intersection(a,b,c)	S_ssc_intersection(aTHX_ a,b,c)
#define ssc_is_anything		S_ssc_is_anything
#define ssc_is_cp_posixl_init	S_ssc_is_cp_posixl_init
#define ssc_or(a,b,c)		S_ssc_or(aTHX_ a,b,c)
#define ssc_union(a,b,c)	S_ssc_union(aTHX_ a,b,c)
#define study_chunk(a,b,c,d,e,f,g,h,i,j,k)	S_study_chunk(aTHX_ a,b,c,d,e,f,g,h,i,j,k)
#  endif
#  if defined(PERL_IN_REGCOMP_C) || defined (PERL_IN_DUMP_C)
#define _invlist_dump(a,b,c,d)	Perl__invlist_dump(aTHX_ a,b,c,d)
#  endif
#  if defined(PERL_IN_REGCOMP_C) || defined(PERL_IN_PERL_C) || defined(PERL_IN_UTF8_C)
#define _invlistEQ(a,b,c)	Perl__invlistEQ(aTHX_ a,b,c)
#define _new_invlist_C_array(a)	Perl__new_invlist_C_array(aTHX_ a)
#  endif
#  if defined(PERL_IN_REGCOMP_C) || defined(PERL_IN_REGEXEC_C)
#define _get_regclass_nonbitmap_data(a,b,c,d,e,f)	Perl__get_regclass_nonbitmap_data(aTHX_ a,b,c,d,e,f)
#ifndef PERL_IMPLICIT_CONTEXT
#define re_printf		Perl_re_printf
#endif
#define regprop(a,b,c,d,e)	Perl_regprop(aTHX_ a,b,c,d,e)
#  endif
#  if defined(PERL_IN_REGCOMP_C) || defined(PERL_IN_REGEXEC_C) || defined(PERL_IN_TOKE_C) || defined(PERL_IN_UTF8_C) || defined(PERL_IN_PP_C)
#define _invlist_contains_cp	S__invlist_contains_cp
#define _invlist_len		S__invlist_len
#define _invlist_search		Perl__invlist_search
#define get_invlist_offset_addr	S_get_invlist_offset_addr
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1239,7 +1239,7 @@
 #define ssc_is_cp_posixl_init	S_ssc_is_cp_posixl_init
 #define ssc_or(a,b,c)		S_ssc_or(aTHX_ a,b,c)
 #define ssc_union(a,b,c)	S_ssc_union(aTHX_ a,b,c)
-#define study_chunk(a,b,c,d,e,f,g,h,i,j,k)	S_study_chunk(aTHX_ a,b,c,d,e,f,g,h,i,j,k)
+#define study_chunk(a,b,c,d,e,f,g,h,i,j,k,l)	S_study_chunk(aTHX_ a,b,c,d,e,f,g,h,i,j,k,l)
 #  endif
 #  if defined(PERL_IN_REGCOMP_C) || defined (PERL_IN_DUMP_C)
 #define _invlist_dump(a,b,c,d)	Perl__invlist_dump(aTHX_ a,b,c,d)
```
