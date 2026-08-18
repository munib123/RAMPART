# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5262_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5262_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1531-1573 of the vulnerable file.

					zend_mm_change_huge_block_size(heap, ptr, new_size, real_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#else
					zend_mm_change_huge_block_size(heap, ptr, new_size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
#endif
					return ptr;
				}
			}
		}
	} else {
		zend_mm_chunk *chunk = (zend_mm_chunk*)ZEND_MM_ALIGNED_BASE(ptr, ZEND_MM_CHUNK_SIZE);
		int page_num = (int)(page_offset / ZEND_MM_PAGE_SIZE);
		zend_mm_page_info info = chunk->map[page_num];
#if ZEND_DEBUG
		size_t real_size = size;

		size = ZEND_MM_ALIGNED_SIZE(size) + ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_debug_info));
#endif

		ZEND_MM_CHECK(chunk->heap == heap, "zend_mm_heap corrupted");
		if (info & ZEND_MM_IS_SRUN) {
			int old_bin_num, bin_num;

			old_bin_num = ZEND_MM_SRUN_BIN_NUM(info);
			old_size = bin_data_size[old_bin_num];
			bin_num = ZEND_MM_SMALL_SIZE_TO_BIN(size);
			if (old_bin_num == bin_num) {
#if ZEND_DEBUG
				dbg = zend_mm_get_debug_info(heap, ptr);
				dbg->size = real_size;
				dbg->filename = __zend_filename;
				dbg->orig_filename = __zend_orig_filename;
				dbg->lineno = __zend_lineno;
				dbg->orig_lineno = __zend_orig_lineno;
#endif
				return ptr;
			}
		} else /* if (info & ZEND_MM_IS_LARGE_RUN) */ {
			ZEND_MM_CHECK(ZEND_MM_ALIGNED_OFFSET(page_offset, ZEND_MM_PAGE_SIZE) == 0, "zend_mm_heap corrupted");
			old_size = ZEND_MM_LRUN_PAGES(info) * ZEND_MM_PAGE_SIZE;
			if (size > ZEND_MM_MAX_SMALL_SIZE && size <= ZEND_MM_MAX_LARGE_SIZE) {
				new_size = ZEND_MM_ALIGNED_SIZE_EX(size, ZEND_MM_PAGE_SIZE);
				if (new_size == old_size) {
#if ZEND_DEBUG
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1548,21 +1548,21 @@
 
 		ZEND_MM_CHECK(chunk->heap == heap, "zend_mm_heap corrupted");
 		if (info & ZEND_MM_IS_SRUN) {
-			int old_bin_num, bin_num;
-
-			old_bin_num = ZEND_MM_SRUN_BIN_NUM(info);
+			int old_bin_num = ZEND_MM_SRUN_BIN_NUM(info);
 			old_size = bin_data_size[old_bin_num];
-			bin_num = ZEND_MM_SMALL_SIZE_TO_BIN(size);
-			if (old_bin_num == bin_num) {
-#if ZEND_DEBUG
-				dbg = zend_mm_get_debug_info(heap, ptr);
-				dbg->size = real_size;
-				dbg->filename = __zend_filename;
-				dbg->orig_filename = __zend_orig_filename;
-				dbg->lineno = __zend_lineno;
-				dbg->orig_lineno = __zend_orig_lineno;
-#endif
-				return ptr;
+			if (size <= ZEND_MM_MAX_SMALL_SIZE) {
+				int bin_num = ZEND_MM_SMALL_SIZE_TO_BIN(size);
+				if (old_bin_num == bin_num) {
+#if ZEND_DEBUG
+					dbg = zend_mm_get_debug_info(heap, ptr);
+					dbg->size = real_size;
+					dbg->filename = __zend_filename;
+					dbg->orig_filename = __zend_orig_filename;
+					dbg->lineno = __zend_lineno;
+					dbg->orig_lineno = __zend_orig_lineno;
+#endif
+					return ptr;
+				}
 			}
 		} else /* if (info & ZEND_MM_IS_LARGE_RUN) */ {
 			ZEND_MM_CHECK(ZEND_MM_ALIGNED_OFFSET(page_offset, ZEND_MM_PAGE_SIZE) == 0, "zend_mm_heap corrupted");
```
