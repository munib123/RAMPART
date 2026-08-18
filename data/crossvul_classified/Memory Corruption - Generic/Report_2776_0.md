# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2776_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2776_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 815-856 of the vulnerable file.

 */
static OPJ_BOOL opj_j2k_merge_ppt(opj_tcp_t *p_tcp,
                                  opj_event_mgr_t * p_manager);


/**
 * Writes the TLM marker (Tile Length Marker)
 *
 * @param       p_stream                                the stream to write data to.
 * @param       p_j2k                           J2K codec.
 * @param       p_manager               the user event manager.
*/
static OPJ_BOOL opj_j2k_write_tlm(opj_j2k_t *p_j2k,
                                  opj_stream_private_t *p_stream,
                                  opj_event_mgr_t * p_manager);

/**
 * Writes the SOT marker (Start of tile-part)
 *
 * @param       p_j2k            J2K codec.
 * @param       p_data           FIXME DOC
 * @param       p_data_written   FIXME DOC
 * @param       p_stream         the stream to write data to.
 * @param       p_manager        the user event manager.
*/
static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                  OPJ_BYTE * p_data,
                                  OPJ_UINT32 * p_data_written,
                                  const opj_stream_private_t *p_stream,
                                  opj_event_mgr_t * p_manager);

/**
 * Reads values from a SOT marker (Start of tile-part)
 *
 * the j2k decoder state is not affected. No side effects, no checks except for p_header_size.
 *
 * @param       p_header_data   the data contained in the SOT marker.
 * @param       p_header_size   the size of the data contained in the SOT marker.
 * @param       p_tile_no       Isot.
 * @param       p_tot_len       Psot.
 * @param       p_current_part  TPsot.
 * @param       p_num_parts     TNsot.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -832,13 +832,15 @@
  * Writes the SOT marker (Start of tile-part)
  *
  * @param       p_j2k            J2K codec.
- * @param       p_data           FIXME DOC
- * @param       p_data_written   FIXME DOC
+ * @param       p_data           Output buffer
+ * @param       p_total_data_size Output buffer size
+ * @param       p_data_written   Number of bytes written into stream
  * @param       p_stream         the stream to write data to.
  * @param       p_manager        the user event manager.
 */
 static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                   OPJ_BYTE * p_data,
+                                  OPJ_UINT32 p_total_data_size,
                                   OPJ_UINT32 * p_data_written,
                                   const opj_stream_private_t *p_stream,
                                   opj_event_mgr_t * p_manager);
@@ -4201,6 +4203,7 @@
 
 static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                   OPJ_BYTE * p_data,
+                                  OPJ_UINT32 p_total_data_size,
                                   OPJ_UINT32 * p_data_written,
                                   const opj_stream_private_t *p_stream,
                                   opj_event_mgr_t * p_manager
@@ -4213,6 +4216,12 @@
 
     OPJ_UNUSED(p_stream);
     OPJ_UNUSED(p_manager);
+
+    if (p_total_data_size < 12) {
+        opj_event_msg(p_manager, EVT_ERROR,
+                      "Not enough bytes in output buffer to write SOT marker\n");
+        return OPJ_FALSE;
+    }
 
     opj_write_bytes(p_data, J2K_MS_SOT,
                     2);                                 /* SOT */
@@ -11480,7 +11489,8 @@
 
     l_current_nb_bytes_written = 0;
     l_begin_data = p_data;
-    if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
+    if (! opj_j2k_write_sot(p_j2k, p_data, p_total_data_size,
+                            &l_current_nb_bytes_written, p_stream,
                             p_manager)) {
         return OPJ_FALSE;
     }
@@ -11572,7 +11582,10 @@
         l_part_tile_size = 0;
         l_begin_data = p_data;
 
-        if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
+        if (! opj_j2k_write_sot(p_j2k, p_data,
+                                p_total_data_size,
+                                &l_current_nb_bytes_written,
+                                p_stream,
                                 p_manager)) {
             return OPJ_FALSE;
         }
@@ -11615,7 +11628,9 @@
             l_part_tile_size = 0;
             l_begin_data = p_data;
 
-            if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
+            if (! opj_j2k_write_sot(p_j2k, p_data,
+                                    p_total_data_size,
+                                    &l_current_nb_bytes_written, p_stream,
                                     p_manager)) {
                 return OPJ_FALSE;
             }
```
