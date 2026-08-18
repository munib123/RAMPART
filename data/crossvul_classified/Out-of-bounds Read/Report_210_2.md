# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 210_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `210_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 467-507 of the vulnerable file.

	u32 i;
	GF_ProgressiveDownloadBox *p = (GF_ProgressiveDownloadBox *)a;
	gf_isom_box_dump_start(a, "ProgressiveDownloadBox", trace);
	fprintf(trace, ">\n");

	if (p->size) {
		for (i=0; i<p->count; i++) {
			fprintf(trace, "<DownloadInfo rate=\"%d\" estimatedTime=\"%d\" />\n", p->rates[i], p->times[i]);
		}
	} else {
		fprintf(trace, "<DownloadInfo rate=\"\" estimatedTime=\"\" />\n");
	}
	gf_isom_box_dump_done("ProgressiveDownloadBox", a, trace);
	return GF_OK;
}

GF_Err hdlr_dump(GF_Box *a, FILE * trace)
{
	GF_HandlerBox *p = (GF_HandlerBox *)a;
	gf_isom_box_dump_start(a, "HandlerBox", trace);
	if (p->nameUTF8 && (u32) p->nameUTF8[0] == strlen(p->nameUTF8+1)) {
		fprintf(trace, "hdlrType=\"%s\" Name=\"%s\" ", gf_4cc_to_str(p->handlerType), p->nameUTF8+1);
	} else {
		fprintf(trace, "hdlrType=\"%s\" Name=\"%s\" ", gf_4cc_to_str(p->handlerType), p->nameUTF8);
	}
	fprintf(trace, "reserved1=\"%d\" reserved2=\"", p->reserved1);
	dump_data(trace, (char *) p->reserved2, 12);
	fprintf(trace, "\"");

	fprintf(trace, ">\n");
	gf_isom_box_dump_done("HandlerBox", a, trace);
	return GF_OK;
}

GF_Err iods_dump(GF_Box *a, FILE * trace)
{
	GF_ObjectDescriptorBox *p;

	p = (GF_ObjectDescriptorBox *)a;
	gf_isom_box_dump_start(a, "ObjectDescriptorBox", trace);
	fprintf(trace, ">\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -484,7 +484,7 @@
 {
 	GF_HandlerBox *p = (GF_HandlerBox *)a;
 	gf_isom_box_dump_start(a, "HandlerBox", trace);
-	if (p->nameUTF8 && (u32) p->nameUTF8[0] == strlen(p->nameUTF8+1)) {
+	if (p->nameUTF8 && (u32) p->nameUTF8[0] == strlen(p->nameUTF8)-1) {
 		fprintf(trace, "hdlrType=\"%s\" Name=\"%s\" ", gf_4cc_to_str(p->handlerType), p->nameUTF8+1);
 	} else {
 		fprintf(trace, "hdlrType=\"%s\" Name=\"%s\" ", gf_4cc_to_str(p->handlerType), p->nameUTF8);
@@ -4157,9 +4157,9 @@
 		fprintf(trace, " maxPicWidth=\"%u\" maxPicHeight=\"%u\"", op->maxPicWidth, op->maxPicHeight);
 		fprintf(trace, " maxChromaFormat=\"%u\" maxBitDepth=\"%u\"", op->maxChromaFormat, op->maxBitDepth);
 		fprintf(trace, " frame_rate_info_flag=\"%u\" bit_rate_info_flag=\"%u\"", op->frame_rate_info_flag, op->bit_rate_info_flag);
-		if (op->frame_rate_info_flag) 
+		if (op->frame_rate_info_flag)
 			fprintf(trace, " avgFrameRate=\"%u\" constantFrameRate=\"%u\"", op->avgFrameRate, op->constantFrameRate);
-		if (op->bit_rate_info_flag) 
+		if (op->bit_rate_info_flag)
 			fprintf(trace, " maxBitRate=\"%u\" avgBitRate=\"%u\"", op->maxBitRate, op->avgBitRate);
 		fprintf(trace, "/>\n");
 	}
@@ -4261,14 +4261,14 @@
 		fprintf(trace, "</NALUMap>\n");
 		return;
 	}
-	
+
 	bs = gf_bs_new(data, data_size, GF_BITSTREAM_READ);
 	gf_bs_read_int(bs, 6);
 	large_size = gf_bs_read_int(bs, 1);
 	rle = gf_bs_read_int(bs, 1);
 	entry_count = gf_bs_read_int(bs, large_size ? 16 : 8);
 	fprintf(trace, "<NALUMap rle=\"%d\" large_size=\"%d\">\n", rle, large_size);
-	
+
 	while (entry_count) {
 		u32 ID;
 		fprintf(trace, "<NALUMapEntry ");
@@ -4338,7 +4338,7 @@
 		case GF_ISOM_SAMPLE_GROUP_TRIF:
 			trif_dump(trace, (char *) ((GF_DefaultSampleGroupDescriptionEntry*)entry)->data,  ((GF_DefaultSampleGroupDescriptionEntry*)entry)->length);
 			break;
-			
+
 		case GF_ISOM_SAMPLE_GROUP_NALM:
 			nalm_dump(trace, (char *) ((GF_DefaultSampleGroupDescriptionEntry*)entry)->data,  ((GF_DefaultSampleGroupDescriptionEntry*)entry)->length);
 			break;
@@ -4507,7 +4507,7 @@
 		fprintf(trace, "\"  KID=\"");
 	}
 	dump_data_hex(trace, (char *) ptr->KID, 16);
-	if (ptr->version) 
+	if (ptr->version)
 		fprintf(trace, "\" crypt_byte_block=\"%d\" skip_byte_block=\"%d", ptr->crypt_byte_block, ptr->skip_byte_block);
 	fprintf(trace, "\">\n");
 	gf_isom_box_dump_done("TrackEncryptionBox", a, trace);
```
