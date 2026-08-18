# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2456_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2456_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 4052-4092 of the vulnerable file.

	if (e) return e;
	pos = gf_bs_get_position(bs);
	size = (u32) s->size;

	//when cookie is set on bs, always convert qtff-style mp4a to isobmff-style
	//since the conversion is done in addBox and we don't have the bitstream there (arg...), flag the box
 	if (gf_bs_get_cookie(bs)) {
 		ptr->is_qtff |= 1<<16;
 	}

	e = gf_isom_box_array_read(s, bs, audio_sample_entry_AddBox);
	if (!e) return GF_OK;
	if (size<8) return GF_ISOM_INVALID_FILE;

	/*hack for some weird files (possibly recorded with live.com tools, needs further investigations)*/
	gf_bs_seek(bs, pos);
	data = (char*)gf_malloc(sizeof(char) * size);
	gf_bs_read_data(bs, data, size);
	for (i=0; i<size-8; i++) {
		if (GF_4CC((u32)data[i+4], (u8)data[i+5], (u8)data[i+6], (u8)data[i+7]) == GF_ISOM_BOX_TYPE_ESDS) {
			GF_BitStream *mybs = gf_bs_new(data + i, size - i, GF_BITSTREAM_READ);
			if (ptr->esd) {
				gf_isom_box_del((GF_Box *)ptr->esd);
				ptr->esd=NULL;
			}

			e = gf_isom_box_parse((GF_Box **)&ptr->esd, mybs);

			if (e==GF_OK) {
				gf_isom_box_add_for_dump_mode((GF_Box*)ptr, (GF_Box*)ptr->esd);
			} else if (ptr->esd) {
				gf_isom_box_del((GF_Box *)ptr->esd);
				ptr->esd=NULL;
			}

			gf_bs_del(mybs);
			break;
		}
	}
	gf_free(data);
	return e;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4069,9 +4069,10 @@
 	gf_bs_read_data(bs, data, size);
 	for (i=0; i<size-8; i++) {
 		if (GF_4CC((u32)data[i+4], (u8)data[i+5], (u8)data[i+6], (u8)data[i+7]) == GF_ISOM_BOX_TYPE_ESDS) {
+			extern Bool use_dump_mode;
 			GF_BitStream *mybs = gf_bs_new(data + i, size - i, GF_BITSTREAM_READ);
 			if (ptr->esd) {
-				gf_isom_box_del((GF_Box *)ptr->esd);
+				if (!use_dump_mode) gf_isom_box_del((GF_Box *)ptr->esd);
 				ptr->esd=NULL;
 			}
 
```
