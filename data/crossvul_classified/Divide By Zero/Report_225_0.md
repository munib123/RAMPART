# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 225_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `225_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 3150-3191 of the vulnerable file.

   }
}

void /* PRIVATE */
png_check_chunk_length(png_const_structrp png_ptr, const png_uint_32 length)
{
   png_alloc_size_t limit = PNG_UINT_31_MAX;

# ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (png_ptr->user_chunk_malloc_max > 0 &&
       png_ptr->user_chunk_malloc_max < limit)
      limit = png_ptr->user_chunk_malloc_max;
# elif PNG_USER_CHUNK_MALLOC_MAX > 0
   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
      limit = PNG_USER_CHUNK_MALLOC_MAX;
# endif
   if (png_ptr->chunk_name == png_IDAT)
   {
      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
      size_t row_factor =
         (png_ptr->width * png_ptr->channels * (png_ptr->bit_depth > 8? 2: 1)
          + 1 + (png_ptr->interlaced? 6: 0));
      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
         idat_limit=PNG_UINT_31_MAX;
      else
         idat_limit = png_ptr->height * row_factor;
      row_factor = row_factor > 32566? 32566 : row_factor;
      idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */
      idat_limit=idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
      limit = limit < idat_limit? idat_limit : limit;
   }

   if (length > limit)
   {
      png_debug2(0," length = %lu, limit = %lu",
         (unsigned long)length,(unsigned long)limit);
      png_chunk_error(png_ptr, "chunk data is too large");
   }
}

/* Combines the row recently read in with the existing pixels in the row.  This
 * routine takes care of alpha and transparency if requested.  This routine also
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3167,10 +3167,13 @@
    {
       png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
       size_t row_factor =
-         (png_ptr->width * png_ptr->channels * (png_ptr->bit_depth > 8? 2: 1)
-          + 1 + (png_ptr->interlaced? 6: 0));
+         (size_t)png_ptr->width
+         * (size_t)png_ptr->channels
+         * (png_ptr->bit_depth > 8? 2: 1)
+         + 1
+         + (png_ptr->interlaced? 6: 0);
       if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
-         idat_limit=PNG_UINT_31_MAX;
+         idat_limit = PNG_UINT_31_MAX;
       else
          idat_limit = png_ptr->height * row_factor;
       row_factor = row_factor > 32566? 32566 : row_factor;
```
