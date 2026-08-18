# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3369_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3369_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 41-81 of the vulnerable file.

}

struct iwjpegrcontext {
	struct jpeg_source_mgr pub; // This field must be first.
	struct iw_context *ctx;
	struct iw_iodescr *iodescr;
	JOCTET *buffer;
	size_t buffer_len;
	int is_jfif;
	unsigned int exif_orientation; // 0 means not set
	double exif_density_x, exif_density_y; // -1.0 means not set.
	unsigned int exif_density_unit; // 0 means not set
};

struct iw_exif_state {
	int endian;
	const iw_byte *d;
	size_t d_len;
};

// Try to read an Exif tag into an integer.
// Returns zero on failure.
static int get_exif_tag_int_value(struct iw_exif_state *e, unsigned int tag_pos,
	unsigned int *pv)
{
	unsigned int field_type;
	unsigned int value_count;

	field_type = iw_get_ui16_e(&e->d[tag_pos+2],e->endian);
	value_count = iw_get_ui32_e(&e->d[tag_pos+4],e->endian);

	if(value_count!=1) return 0;

	if(field_type==3) { // SHORT (uint16)
		*pv = iw_get_ui16_e(&e->d[tag_pos+8],e->endian);
		return 1;
	}
	else if(field_type==4) { // LONG (uint32)
		*pv = iw_get_ui32_e(&e->d[tag_pos+8],e->endian);
		return 1;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,18 @@
 	size_t d_len;
 };
 
+static unsigned int get_exif_ui16(struct iw_exif_state *e, unsigned int pos)
+{
+	if(e->d_len<2 || pos>e->d_len-2) return 0;
+	return iw_get_ui16_e(&e->d[pos], e->endian);
+}
+
+static unsigned int get_exif_ui32(struct iw_exif_state *e, unsigned int pos)
+{
+	if(e->d_len<4 || pos>e->d_len-4) return 0;
+	return iw_get_ui32_e(&e->d[pos], e->endian);
+}
+
 // Try to read an Exif tag into an integer.
 // Returns zero on failure.
 static int get_exif_tag_int_value(struct iw_exif_state *e, unsigned int tag_pos,
@@ -66,17 +78,17 @@
 	unsigned int field_type;
 	unsigned int value_count;
 
-	field_type = iw_get_ui16_e(&e->d[tag_pos+2],e->endian);
-	value_count = iw_get_ui32_e(&e->d[tag_pos+4],e->endian);
+	field_type = get_exif_ui16(e, tag_pos+2);
+	value_count = get_exif_ui32(e, tag_pos+4);
 
 	if(value_count!=1) return 0;
 
 	if(field_type==3) { // SHORT (uint16)
-		*pv = iw_get_ui16_e(&e->d[tag_pos+8],e->endian);
+		*pv = get_exif_ui16(e, tag_pos+8);
 		return 1;
 	}
 	else if(field_type==4) { // LONG (uint32)
-		*pv = iw_get_ui32_e(&e->d[tag_pos+8],e->endian);
+		*pv = get_exif_ui32(e, tag_pos+8);
 		return 1;
 	}
 
@@ -93,8 +105,8 @@
 	unsigned int value_pos;
 	unsigned int numer, denom;
 
-	field_type = iw_get_ui16_e(&e->d[tag_pos+2],e->endian);
-	value_count = iw_get_ui32_e(&e->d[tag_pos+4],e->endian);
+	field_type = get_exif_ui16(e, tag_pos+2);
+	value_count = get_exif_ui32(e, tag_pos+4);
 
 	if(value_count!=1) return 0;
 
@@ -103,12 +115,12 @@
 	// A rational is 8 bytes. Since 8>4, it is stored indirectly. First, read
 	// the location where it is stored.
 
-	value_pos = iw_get_ui32_e(&e->d[tag_pos+8],e->endian);
+	value_pos = get_exif_ui32(e, tag_pos+8);
 	if(value_pos > e->d_len-8) return 0;
 
 	// Read the actual value.
-	numer = iw_get_ui32_e(&e->d[value_pos  ],e->endian);
-	denom = iw_get_ui32_e(&e->d[value_pos+4],e->endian);
+	numer = get_exif_ui32(e, value_pos);
+	denom = get_exif_ui32(e, value_pos+4);
 	if(denom==0) return 0;
 
 	*pv = ((double)numer)/denom;
@@ -125,15 +137,15 @@
 	unsigned int v;
 	double v_dbl;
 
-	if(ifd<8 || ifd>e->d_len-18) return;
-
-	tag_count = iw_get_ui16_e(&e->d[ifd],e->endian);
+	if(ifd<8 || e->d_len<18 || ifd>e->d_len-18) return;
+
+	tag_count = get_exif_ui16(e, ifd);
 	if(tag_count>1000) return; // Sanity check.
 
 	for(i=0;i<tag_count;i++) {
 		tag_pos = ifd+2+i*12;
 		if(tag_pos+12 > e->d_len) return; // Avoid overruns.
-		tag_id = iw_get_ui16_e(&e->d[tag_pos],e->endian);
+		tag_id = get_exif_ui16(e, tag_pos);
 
 		switch(tag_id) {
 		case 274: // 274 = Orientation
@@ -177,7 +189,7 @@
 
 	e.endian = d[0]=='I' ? IW_ENDIAN_LITTLE : IW_ENDIAN_BIG;
 
-	ifd = iw_get_ui32_e(&d[4],e.endian);
+	ifd = get_exif_ui32(&e, 4);
 
 	iwjpeg_scan_exif_ifd(rctx,&e,ifd);
 }
```
