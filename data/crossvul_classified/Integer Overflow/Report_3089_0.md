# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3089_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3089_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 158-198 of the vulnerable file.


static void zend_always_inline zend_hash_check_init(HashTable *ht, int packed)
{
	HT_ASSERT(GC_REFCOUNT(ht) == 1);
	if (UNEXPECTED(!((ht)->u.flags & HASH_FLAG_INITIALIZED))) {
		zend_hash_real_init_ex(ht, packed);
	}
}

#define CHECK_INIT(ht, packed) \
	zend_hash_check_init(ht, packed)

static const uint32_t uninitialized_bucket[-HT_MIN_MASK] =
	{HT_INVALID_IDX, HT_INVALID_IDX};

ZEND_API void ZEND_FASTCALL _zend_hash_init(HashTable *ht, uint32_t nSize, dtor_func_t pDestructor, zend_bool persistent ZEND_FILE_LINE_DC)
{
	GC_REFCOUNT(ht) = 1;
	GC_TYPE_INFO(ht) = IS_ARRAY;
	ht->u.flags = (persistent ? HASH_FLAG_PERSISTENT : 0) | HASH_FLAG_APPLY_PROTECTION | HASH_FLAG_STATIC_KEYS;
	ht->nTableSize = zend_hash_check_size(nSize);
	ht->nTableMask = HT_MIN_MASK;
	HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
	ht->nNumUsed = 0;
	ht->nNumOfElements = 0;
	ht->nInternalPointer = HT_INVALID_IDX;
	ht->nNextFreeElement = 0;
	ht->pDestructor = pDestructor;
}

static void ZEND_FASTCALL zend_hash_packed_grow(HashTable *ht)
{
	HT_ASSERT(GC_REFCOUNT(ht) == 1);
	if (ht->nTableSize >= HT_MAX_SIZE) {
		zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", ht->nTableSize * 2, sizeof(Bucket), sizeof(Bucket));
	}
	HANDLE_BLOCK_INTERRUPTIONS();
	ht->nTableSize += ht->nTableSize;
	HT_SET_DATA_ADDR(ht, perealloc2(HT_GET_DATA_ADDR(ht), HT_SIZE(ht), HT_USED_SIZE(ht), ht->u.flags & HASH_FLAG_PERSISTENT));
	HANDLE_UNBLOCK_INTERRUPTIONS();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -175,7 +175,6 @@
 	GC_REFCOUNT(ht) = 1;
 	GC_TYPE_INFO(ht) = IS_ARRAY;
 	ht->u.flags = (persistent ? HASH_FLAG_PERSISTENT : 0) | HASH_FLAG_APPLY_PROTECTION | HASH_FLAG_STATIC_KEYS;
-	ht->nTableSize = zend_hash_check_size(nSize);
 	ht->nTableMask = HT_MIN_MASK;
 	HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
 	ht->nNumUsed = 0;
@@ -183,6 +182,7 @@
 	ht->nInternalPointer = HT_INVALID_IDX;
 	ht->nNextFreeElement = 0;
 	ht->pDestructor = pDestructor;
+	ht->nTableSize = zend_hash_check_size(nSize);
 }
 
 static void ZEND_FASTCALL zend_hash_packed_grow(HashTable *ht)
```
