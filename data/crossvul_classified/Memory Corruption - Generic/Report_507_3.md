# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 507_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `507_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 100-140 of the vulnerable file.

  l_csc_file_handle = fopen( i_csc_file_in, "r" );
  if ( l_csc_file_handle == NULL ) {
    LIBXSMM_HANDLE_ERROR( io_generated_code, LIBXSMM_ERR_CSC_INPUT );
    return;
  }

  while (fgets(l_line, l_line_length, l_csc_file_handle) != NULL) {
    if ( strlen(l_line) == l_line_length ) {
      free(*o_row_idx); free(*o_column_idx); free(*o_values); free(l_column_idx_id);
      *o_row_idx = 0; *o_column_idx = 0; *o_values = 0;
      fclose( l_csc_file_handle ); /* close mtx file */
      LIBXSMM_HANDLE_ERROR( io_generated_code, LIBXSMM_ERR_CSC_READ_LEN );
      return;
    }
    /* check if we are still reading comments header */
    if ( l_line[0] == '%' ) {
      continue;
    } else {
      /* if we are the first line after comment header, we allocate our data structures */
      if ( l_header_read == 0 ) {
        if ( sscanf(l_line, "%u %u %u", o_row_count, o_column_count, o_element_count) == 3 ) {
          /* allocate CSC data structure matching mtx file */
          *o_row_idx = (unsigned int*) malloc(sizeof(unsigned int) * (*o_element_count));
          *o_column_idx = (unsigned int*) malloc(sizeof(unsigned int) * ((size_t)(*o_column_count) + 1));
          *o_values = (double*) malloc(sizeof(double) * (*o_element_count));
          l_column_idx_id = (unsigned int*) malloc(sizeof(unsigned int) * (*o_column_count));

          /* check if mallocs were successful */
          if ( ( *o_row_idx == NULL )      ||
               ( *o_column_idx == NULL )   ||
               ( *o_values == NULL )       ||
               ( l_column_idx_id == NULL ) ) {
            free(*o_row_idx); free(*o_column_idx); free(*o_values); free(l_column_idx_id);
            *o_row_idx = 0; *o_column_idx = 0; *o_values = 0;
            fclose(l_csc_file_handle); /* close mtx file */
            LIBXSMM_HANDLE_ERROR( io_generated_code, LIBXSMM_ERR_CSC_ALLOC_DATA );
            return;
          }

          /* set everything to zero for init */
          memset(*o_row_idx, 0, sizeof(unsigned int) * (*o_element_count));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,7 +117,9 @@
     } else {
       /* if we are the first line after comment header, we allocate our data structures */
       if ( l_header_read == 0 ) {
-        if ( sscanf(l_line, "%u %u %u", o_row_count, o_column_count, o_element_count) == 3 ) {
+        if (3 == sscanf(l_line, "%u %u %u", o_row_count, o_column_count, o_element_count) &&
+            0 != *o_row_count && 0 != *o_column_count && 0 != *o_element_count)
+        {
           /* allocate CSC data structure matching mtx file */
           *o_row_idx = (unsigned int*) malloc(sizeof(unsigned int) * (*o_element_count));
           *o_column_idx = (unsigned int*) malloc(sizeof(unsigned int) * ((size_t)(*o_column_count) + 1));
@@ -168,8 +170,8 @@
           return;
         }
         /* adjust numbers to zero termination */
-        l_row--;
-        l_column--;
+        LIBXSMM_ASSERT(0 != l_row && 0 != l_column);
+        l_row--; l_column--;
         /* add these values to row and value structure */
         (*o_row_idx)[l_i] = l_row;
         (*o_values)[l_i] = l_value;
@@ -205,4 +207,3 @@
   }
 }
 
-
```
