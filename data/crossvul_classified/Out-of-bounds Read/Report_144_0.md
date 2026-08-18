# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 144_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `144_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2715-2756 of the vulnerable file.

	R_FREE (cv_nb10_header->file_name);
}

static void init_cv_nb10_header(SCV_NB10_HEADER* cv_nb10_header) {
	memset (cv_nb10_header, 0, sizeof (SCV_NB10_HEADER));
	cv_nb10_header->free = (void (*)(struct SCV_NB10_HEADER*))free_cv_nb10_header;
}

static bool get_rsds(ut8* dbg_data, int dbg_data_len, SCV_RSDS_HEADER* res) {
	const int rsds_sz = 4 + sizeof (SGUID) + 4;
	if (dbg_data_len < rsds_sz) {
		return false;
	}
	memcpy (res, dbg_data, rsds_sz);
	res->file_name = (ut8*) strdup ((const char*) dbg_data + rsds_sz);
	return true;
}

static void get_nb10(ut8* dbg_data, SCV_NB10_HEADER* res) {
	const int nb10sz = 16;
	memcpy (res, dbg_data, nb10sz);
	res->file_name = (ut8*) strdup ((const char*) dbg_data + nb10sz);
}

static int get_debug_info(struct PE_(r_bin_pe_obj_t)* bin, PE_(image_debug_directory_entry)* dbg_dir_entry, ut8* dbg_data, int dbg_data_len, SDebugInfo* res) {
	#define SIZEOF_FILE_NAME 255
	int i = 0;
	const char* basename;
	if (!dbg_data) {
		return 0;
	}
	switch (dbg_dir_entry->Type) {
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		if (!strncmp ((char*) dbg_data, "RSDS", 4)) {
			SCV_RSDS_HEADER rsds_hdr;
			init_rsdr_hdr (&rsds_hdr);
			if (!get_rsds (dbg_data, dbg_data_len, &rsds_hdr)) {
				bprintf ("Warning: Cannot read PE debug info\n");
				return 0;
			}
			snprintf (res->guidstr, GUIDSTR_LEN,
				"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2732,8 +2732,8 @@
 
 static void get_nb10(ut8* dbg_data, SCV_NB10_HEADER* res) {
 	const int nb10sz = 16;
-	memcpy (res, dbg_data, nb10sz);
-	res->file_name = (ut8*) strdup ((const char*) dbg_data + nb10sz);
+	// memcpy (res, dbg_data, nb10sz);
+	// res->file_name = (ut8*) strdup ((const char*) dbg_data + nb10sz);
 }
 
 static int get_debug_info(struct PE_(r_bin_pe_obj_t)* bin, PE_(image_debug_directory_entry)* dbg_dir_entry, ut8* dbg_data, int dbg_data_len, SDebugInfo* res) {
@@ -2772,13 +2772,20 @@
 			res->file_name[sizeof (res->file_name) - 1] = 0;
 			rsds_hdr.free ((struct SCV_RSDS_HEADER*) &rsds_hdr);
 		} else if (strncmp ((const char*) dbg_data, "NB10", 4) == 0) {
-			SCV_NB10_HEADER nb10_hdr;
+			if (dbg_data_len < 20) {
+				eprintf ("Truncated NB10 entry, not enough data to parse\n");
+				return 0;
+			}
+			SCV_NB10_HEADER nb10_hdr = {{0}};
 			init_cv_nb10_header (&nb10_hdr);
 			get_nb10 (dbg_data, &nb10_hdr);
 			snprintf (res->guidstr, sizeof (res->guidstr),
 				"%x%x", nb10_hdr.timestamp, nb10_hdr.age);
-			strncpy (res->file_name, (const char*)
-				nb10_hdr.file_name, sizeof(res->file_name) - 1);
+			res->file_name[0] = 0;
+			if (nb10_hdr.file_name) {
+				strncpy (res->file_name, (const char*)
+						nb10_hdr.file_name, sizeof (res->file_name) - 1);
+			}
 			res->file_name[sizeof (res->file_name) - 1] = 0;
 			nb10_hdr.free ((struct SCV_NB10_HEADER*) &nb10_hdr);
 		} else {
```
