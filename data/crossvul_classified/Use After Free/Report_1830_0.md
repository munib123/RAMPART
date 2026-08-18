# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1830_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1830_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 5542-5583 of the vulnerable file.

        return OPJ_TRUE;
}

static OPJ_BOOL opj_j2k_write_mco(     opj_j2k_t *p_j2k,
                                                struct opj_stream_private *p_stream,
                                                struct opj_event_mgr * p_manager
                                  )
{
        OPJ_BYTE * l_current_data = 00;
        OPJ_UINT32 l_mco_size;
        opj_tcp_t * l_tcp = 00;
        opj_simple_mcc_decorrelation_data_t * l_mcc_record;
        OPJ_UINT32 i;

        /* preconditions */
        assert(p_j2k != 00);
        assert(p_manager != 00);
        assert(p_stream != 00);

        l_tcp =&(p_j2k->m_cp.tcps[p_j2k->m_current_tile_number]);
        l_current_data = p_j2k->m_specific_param.m_encoder.m_header_tile_data;

        l_mco_size = 5 + l_tcp->m_nb_mcc_records;
        if (l_mco_size > p_j2k->m_specific_param.m_encoder.m_header_tile_data_size) {

                OPJ_BYTE *new_header_tile_data = (OPJ_BYTE *) opj_realloc(p_j2k->m_specific_param.m_encoder.m_header_tile_data, l_mco_size);
                if (! new_header_tile_data) {
                        opj_free(p_j2k->m_specific_param.m_encoder.m_header_tile_data);
                        p_j2k->m_specific_param.m_encoder.m_header_tile_data = NULL;
                        p_j2k->m_specific_param.m_encoder.m_header_tile_data_size = 0;
                        opj_event_msg(p_manager, EVT_ERROR, "Not enough memory to write MCO marker\n");
                        return OPJ_FALSE;
                }
                p_j2k->m_specific_param.m_encoder.m_header_tile_data = new_header_tile_data;
                p_j2k->m_specific_param.m_encoder.m_header_tile_data_size = l_mco_size;
        }

        opj_write_bytes(l_current_data,J2K_MS_MCO,2);                   /* MCO */
        l_current_data += 2;

        opj_write_bytes(l_current_data,l_mco_size-2,2);                 /* Lmco */
        l_current_data += 2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5559,8 +5559,7 @@
         assert(p_stream != 00);
 
         l_tcp =&(p_j2k->m_cp.tcps[p_j2k->m_current_tile_number]);
-        l_current_data = p_j2k->m_specific_param.m_encoder.m_header_tile_data;
-
+	
         l_mco_size = 5 + l_tcp->m_nb_mcc_records;
         if (l_mco_size > p_j2k->m_specific_param.m_encoder.m_header_tile_data_size) {
 
@@ -5575,6 +5574,8 @@
                 p_j2k->m_specific_param.m_encoder.m_header_tile_data = new_header_tile_data;
                 p_j2k->m_specific_param.m_encoder.m_header_tile_data_size = l_mco_size;
         }
+        l_current_data = p_j2k->m_specific_param.m_encoder.m_header_tile_data;
+
 
         opj_write_bytes(l_current_data,J2K_MS_MCO,2);                   /* MCO */
         l_current_data += 2;
@@ -5586,10 +5587,9 @@
         ++l_current_data;
 
         l_mcc_record = l_tcp->m_mcc_records;
-        for     (i=0;i<l_tcp->m_nb_mcc_records;++i) {
+        for (i=0;i<l_tcp->m_nb_mcc_records;++i) {
                 opj_write_bytes(l_current_data,l_mcc_record->m_index,1);/* Imco -> use the mcc indicated by 1*/
                 ++l_current_data;
-
                 ++l_mcc_record;
         }
 
```
