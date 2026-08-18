# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 32-74 of the vulnerable file.

#define HSE_LEN(he_) (HSE_ISFIRST(he_)	\
					  ? HSE_ENDPOS(he_) \
					  : HSE_ENDPOS(he_) - HSE_ENDPOS((&(he_))[-1]))

/*
 * determined by the size of "endpos" (ie HENTRY_POSMASK), though this is a
 * bit academic since currently varlenas (and hence both the input and the
 * whole hstore) have the same limit
 */
#define HSTORE_MAX_KEY_LEN 0x3FFFFFFF
#define HSTORE_MAX_VALUE_LEN 0x3FFFFFFF

typedef struct
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	uint32		size_;			/* flags and number of items in hstore */
	/* array of HEntry follows */
} HStore;

/*
 * it's not possible to get more than 2^28 items into an hstore,
 * so we reserve the top few bits of the size field. See hstore_compat.c
 * for one reason why.	Some bits are left for future use here.
 */
#define HS_FLAG_NEWVERSION 0x80000000

#define HS_COUNT(hsp_) ((hsp_)->size_ & 0x0FFFFFFF)
#define HS_SETCOUNT(hsp_,c_) ((hsp_)->size_ = (c_) | HS_FLAG_NEWVERSION)


#define HSHRDSIZE	(sizeof(HStore))
#define CALCDATASIZE(x, lenstr) ( (x) * 2 * sizeof(HEntry) + HSHRDSIZE + (lenstr) )

/* note multiple evaluations of x */
#define ARRPTR(x)		( (HEntry*) ( (HStore*)(x) + 1 ) )
#define STRPTR(x)		( (char*)(ARRPTR(x) + HS_COUNT((HStore*)(x)) * 2) )

/* note multiple/non evaluations */
#define HS_KEY(arr_,str_,i_) ((str_) + HSE_OFF((arr_)[2*(i_)]))
#define HS_VAL(arr_,str_,i_) ((str_) + HSE_OFF((arr_)[2*(i_)+1]))
#define HS_KEYLEN(arr_,i_) (HSE_LEN((arr_)[2*(i_)]))
#define HS_VALLEN(arr_,i_) (HSE_LEN((arr_)[2*(i_)+1]))
#define HS_VALISNULL(arr_,i_) (HSE_ISNULL((arr_)[2*(i_)+1]))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,9 +49,12 @@
 } HStore;
 
 /*
- * it's not possible to get more than 2^28 items into an hstore,
- * so we reserve the top few bits of the size field. See hstore_compat.c
- * for one reason why.	Some bits are left for future use here.
+ * It's not possible to get more than 2^28 items into an hstore, so we reserve
+ * the top few bits of the size field.  See hstore_compat.c for one reason
+ * why.  Some bits are left for future use here.  MaxAllocSize makes the
+ * practical count limit slightly more than 2^28 / 3, or INT_MAX / 24, the
+ * limit for an hstore full of 4-byte keys and null values.  Therefore, we
+ * don't explicitly check the format-imposed limit.
  */
 #define HS_FLAG_NEWVERSION 0x80000000
 
@@ -59,6 +62,12 @@
 #define HS_SETCOUNT(hsp_,c_) ((hsp_)->size_ = (c_) | HS_FLAG_NEWVERSION)
 
 
+/*
+ * "x" comes from an existing HS_COUNT() (as discussed, <= INT_MAX/24) or a
+ * Pairs array length (due to MaxAllocSize, <= INT_MAX/40).  "lenstr" is no
+ * more than INT_MAX, that extreme case arising in hstore_from_arrays().
+ * Therefore, this calculation is limited to about INT_MAX / 5 + INT_MAX.
+ */
 #define HSHRDSIZE	(sizeof(HStore))
 #define CALCDATASIZE(x, lenstr) ( (x) * 2 * sizeof(HEntry) + HSHRDSIZE + (lenstr) )
 
```
