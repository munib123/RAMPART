# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4012_2
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4012_2`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 5642-5682 of the vulnerable file.

	assert(ssc); assert(invlist)
#endif
STATIC int	S_ssc_is_anything(const regnode_ssc *ssc)
			__attribute__warn_unused_result__;
#define PERL_ARGS_ASSERT_SSC_IS_ANYTHING	\
	assert(ssc)

STATIC int	S_ssc_is_cp_posixl_init(const RExC_state_t *pRExC_state, const regnode_ssc *ssc)
			__attribute__warn_unused_result__;
#define PERL_ARGS_ASSERT_SSC_IS_CP_POSIXL_INIT	\
	assert(pRExC_state); assert(ssc)

STATIC void	S_ssc_or(pTHX_ const RExC_state_t *pRExC_state, regnode_ssc *ssc, const regnode_charclass *or_with);
#define PERL_ARGS_ASSERT_SSC_OR	\
	assert(pRExC_state); assert(ssc); assert(or_with)
#ifndef PERL_NO_INLINE_FUNCTIONS
PERL_STATIC_INLINE void	S_ssc_union(pTHX_ regnode_ssc *ssc, SV* const invlist, const bool invert_2nd);
#define PERL_ARGS_ASSERT_SSC_UNION	\
	assert(ssc); assert(invlist)
#endif
STATIC SSize_t	S_study_chunk(pTHX_ RExC_state_t *pRExC_state, regnode **scanp, SSize_t *minlenp, SSize_t *deltap, regnode *last, struct scan_data_t *data, I32 stopparen, U32 recursed_depth, regnode_ssc *and_withp, U32 flags, U32 depth);
#define PERL_ARGS_ASSERT_STUDY_CHUNK	\
	assert(pRExC_state); assert(scanp); assert(minlenp); assert(deltap); assert(last)
#endif
#if defined(PERL_IN_REGCOMP_C) || defined (PERL_IN_DUMP_C)
PERL_CALLCONV void	Perl__invlist_dump(pTHX_ PerlIO *file, I32 level, const char* const indent, SV* const invlist);
#define PERL_ARGS_ASSERT__INVLIST_DUMP	\
	assert(file); assert(indent); assert(invlist)
#endif
#if defined(PERL_IN_REGCOMP_C) || defined(PERL_IN_PERL_C) || defined(PERL_IN_UTF8_C)
PERL_CALLCONV bool	Perl__invlistEQ(pTHX_ SV* const a, SV* const b, const bool complement_b);
#define PERL_ARGS_ASSERT__INVLISTEQ	\
	assert(a); assert(b)
PERL_CALLCONV SV*	Perl__new_invlist_C_array(pTHX_ const UV* const list)
			__attribute__warn_unused_result__;
#define PERL_ARGS_ASSERT__NEW_INVLIST_C_ARRAY	\
	assert(list)

#endif
#if defined(PERL_IN_REGCOMP_C) || defined(PERL_IN_REGEXEC_C)
PERL_CALLCONV SV*	Perl__get_regclass_nonbitmap_data(pTHX_ const regexp *prog, const struct regnode *node, bool doinit, SV **listsvp, SV **lonly_utf8_locale, SV **output_invlist);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5659,7 +5659,7 @@
 #define PERL_ARGS_ASSERT_SSC_UNION	\
 	assert(ssc); assert(invlist)
 #endif
-STATIC SSize_t	S_study_chunk(pTHX_ RExC_state_t *pRExC_state, regnode **scanp, SSize_t *minlenp, SSize_t *deltap, regnode *last, struct scan_data_t *data, I32 stopparen, U32 recursed_depth, regnode_ssc *and_withp, U32 flags, U32 depth);
+STATIC SSize_t	S_study_chunk(pTHX_ RExC_state_t *pRExC_state, regnode **scanp, SSize_t *minlenp, SSize_t *deltap, regnode *last, struct scan_data_t *data, I32 stopparen, U32 recursed_depth, regnode_ssc *and_withp, U32 flags, U32 depth, bool was_mutate_ok);
 #define PERL_ARGS_ASSERT_STUDY_CHUNK	\
 	assert(pRExC_state); assert(scanp); assert(minlenp); assert(deltap); assert(last)
 #endif
```
