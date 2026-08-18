# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4865_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4865_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1165-1206 of the vulnerable file.

        }
    }
    if (! p_code_block->passes) {
        p_code_block->passes = (opj_tcd_pass_t*) opj_calloc(100,
                               sizeof(opj_tcd_pass_t));
        if (! p_code_block->passes) {
            return OPJ_FALSE;
        }
    }
    return OPJ_TRUE;
}

/**
 * Allocates data memory for an encoding code block.
 */
static OPJ_BOOL opj_tcd_code_block_enc_allocate_data(opj_tcd_cblk_enc_t *
        p_code_block)
{
    OPJ_UINT32 l_data_size;

    l_data_size = (OPJ_UINT32)((p_code_block->x1 - p_code_block->x0) *
                               (p_code_block->y1 - p_code_block->y0) * (OPJ_INT32)sizeof(OPJ_UINT32));

    if (l_data_size > p_code_block->data_size) {
        if (p_code_block->data) {
            /* We refer to data - 1 since below we incremented it */
            opj_free(p_code_block->data - 1);
        }
        p_code_block->data = (OPJ_BYTE*) opj_malloc(l_data_size + 1);
        if (! p_code_block->data) {
            p_code_block->data_size = 0U;
            return OPJ_FALSE;
        }
        p_code_block->data_size = l_data_size;

        /* We reserve the initial byte as a fake byte to a non-FF value */
        /* and increment the data pointer, so that opj_mqc_init_enc() */
        /* can do bp = data - 1, and opj_mqc_byteout() can safely dereference */
        /* it. */
        p_code_block->data[0] = 0;
        p_code_block->data += 1; /*why +1 ?*/
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1182,8 +1182,9 @@
 {
     OPJ_UINT32 l_data_size;
 
-    l_data_size = (OPJ_UINT32)((p_code_block->x1 - p_code_block->x0) *
-                               (p_code_block->y1 - p_code_block->y0) * (OPJ_INT32)sizeof(OPJ_UINT32));
+    /* The +1 is needed for https://github.com/uclouvain/openjpeg/issues/835 */
+    l_data_size = 1 + (OPJ_UINT32)((p_code_block->x1 - p_code_block->x0) *
+                                   (p_code_block->y1 - p_code_block->y0) * (OPJ_INT32)sizeof(OPJ_UINT32));
 
     if (l_data_size > p_code_block->data_size) {
         if (p_code_block->data) {
```
