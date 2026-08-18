# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1372_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1372_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1135-1175 of the vulnerable file.

	}

	if (pmt->sec->demux_restarted) {
		pmt->sec->demux_restarted = 0;
		return;
	}
	GF_LOG(GF_LOG_DEBUG, GF_LOG_CONTAINER, ("[MPEG-2 TS] PMT Found or updated\n"));

	nb_sections = gf_list_count(sections);
	if (nb_sections > 1) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("PMT on multiple sections not supported\n"));
	}

	section = (GF_M2TS_Section *)gf_list_get(sections, 0);
	data = section->data;
	data_size = section->data_size;

	pmt->program->pcr_pid = ((data[0] & 0x1f) << 8) | data[1];

	info_length = ((data[2]&0xf)<<8) | data[3];
	if (info_length != 0) {
		/* ...Read Descriptors ... */
		u8 tag, len;
		u32 first_loop_len = 0;
		tag = data[4];
		len = data[5];
		while (info_length > first_loop_len) {
			if (tag == GF_M2TS_MPEG4_IOD_DESCRIPTOR) {
				u32 size;
				GF_BitStream *iod_bs;
				iod_bs = gf_bs_new((char *)data+8, len-2, GF_BITSTREAM_READ);
				if (pmt->program->pmt_iod) gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
				e = gf_odf_parse_descriptor(iod_bs , (GF_Descriptor **) &pmt->program->pmt_iod, &size);
				gf_bs_del(iod_bs );
				if (e==GF_OK) {
					/*remember program number for service/program selection*/
					if (pmt->program->pmt_iod) pmt->program->pmt_iod->ServiceID = pmt->program->number;
					/*if empty IOD (freebox case), discard it and use dynamic declaration of object*/
					if (!gf_list_count(pmt->program->pmt_iod->ESDescriptors)) {
						gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
						pmt->program->pmt_iod = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1152,7 +1152,10 @@
 	pmt->program->pcr_pid = ((data[0] & 0x1f) << 8) | data[1];
 
 	info_length = ((data[2]&0xf)<<8) | data[3];
-	if (info_length != 0) {
+	if (info_length + 4 > data_size) {
+		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Broken PMT first loop, %d bytes avail but first loop size %d\n", data_size, info_length));
+		return;
+	} else if (info_length != 0) {
 		/* ...Read Descriptors ... */
 		u8 tag, len;
 		u32 first_loop_len = 0;
@@ -1160,20 +1163,24 @@
 		len = data[5];
 		while (info_length > first_loop_len) {
 			if (tag == GF_M2TS_MPEG4_IOD_DESCRIPTOR) {
-				u32 size;
-				GF_BitStream *iod_bs;
-				iod_bs = gf_bs_new((char *)data+8, len-2, GF_BITSTREAM_READ);
-				if (pmt->program->pmt_iod) gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
-				e = gf_odf_parse_descriptor(iod_bs , (GF_Descriptor **) &pmt->program->pmt_iod, &size);
-				gf_bs_del(iod_bs );
-				if (e==GF_OK) {
-					/*remember program number for service/program selection*/
-					if (pmt->program->pmt_iod) pmt->program->pmt_iod->ServiceID = pmt->program->number;
-					/*if empty IOD (freebox case), discard it and use dynamic declaration of object*/
-					if (!gf_list_count(pmt->program->pmt_iod->ESDescriptors)) {
-						gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
-						pmt->program->pmt_iod = NULL;
+				if ((len>2) && (len - 2 <= info_length)) {
+					u32 size;
+					GF_BitStream *iod_bs;
+					iod_bs = gf_bs_new((char *)data+8, len-2, GF_BITSTREAM_READ);
+					if (pmt->program->pmt_iod) gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
+					e = gf_odf_parse_descriptor(iod_bs , (GF_Descriptor **) &pmt->program->pmt_iod, &size);
+					gf_bs_del(iod_bs );
+					if (e==GF_OK) {
+						/*remember program number for service/program selection*/
+						if (pmt->program->pmt_iod) pmt->program->pmt_iod->ServiceID = pmt->program->number;
+						/*if empty IOD (freebox case), discard it and use dynamic declaration of object*/
+						if (!gf_list_count(pmt->program->pmt_iod->ESDescriptors)) {
+							gf_odf_desc_del((GF_Descriptor *)pmt->program->pmt_iod);
+							pmt->program->pmt_iod = NULL;
+						}
 					}
+				} else {
+					GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Broken IOD! len %d less than 2 bytes to declare IOD\n", len));
 				}
 			} else if (tag == GF_M2TS_METADATA_POINTER_DESCRIPTOR) {
 				GF_BitStream *metadatapd_bs;
```
