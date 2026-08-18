# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2346_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2346_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 720-760 of the vulnerable file.

}
#endif

int cli_scanpe(cli_ctx *ctx)
{
	uint16_t e_magic; /* DOS signature ("MZ") */
	uint16_t nsections;
	uint32_t e_lfanew; /* address of new exe header */
	uint32_t ep, vep; /* entry point (raw, virtual) */
	uint8_t polipos = 0;
	time_t timestamp;
	struct pe_image_file_hdr file_hdr;
	union {
	    struct pe_image_optional_hdr64 opt64;
	    struct pe_image_optional_hdr32 opt32;
	} pe_opt;
	struct pe_image_section_hdr *section_hdr;
	char sname[9], epbuff[4096], *tempfile;
	uint32_t epsize;
	ssize_t bytes, at;
	unsigned int i, found, upx_success = 0, min = 0, max = 0, err, overlays = 0;
	unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0, corrupted_cur;
	int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
	const char *src = NULL;
	char *dest = NULL;
	int ndesc, ret = CL_CLEAN, upack = 0, native=0;
	size_t fsize;
	uint32_t valign, falign, hdr_size, j;
	struct cli_exe_section *exe_sections;
	char timestr[32];
	struct pe_image_data_dir *dirs;
	struct cli_bc_ctx *bc_ctx;
	fmap_t *map;
	struct cli_pe_hook_data pedata;
#ifdef HAVE__INTERNAL__SHA_COLLECT
	int sha_collect = ctx->sha_collect;
#endif
    const char *archtype=NULL, *subsystem=NULL;
	uint32_t viruses_found = 0;
#if HAVE_JSON
        int toval = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -737,14 +737,14 @@
 	char sname[9], epbuff[4096], *tempfile;
 	uint32_t epsize;
 	ssize_t bytes, at;
-	unsigned int i, found, upx_success = 0, min = 0, max = 0, err, overlays = 0;
+	unsigned int i, j, found, upx_success = 0, min = 0, max = 0, err, overlays = 0, rescan = 1;
 	unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0, corrupted_cur;
 	int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
 	const char *src = NULL;
 	char *dest = NULL;
 	int ndesc, ret = CL_CLEAN, upack = 0, native=0;
 	size_t fsize;
-	uint32_t valign, falign, hdr_size, j;
+	uint32_t valign, falign, hdr_size;
 	struct cli_exe_section *exe_sections;
 	char timestr[32];
 	struct pe_image_data_dir *dirs;
@@ -1238,18 +1238,52 @@
     cli_jsonint(pe_json, "NumberOfSections", nsections);
 #endif
 
+    while (rescan==1) {
+        rescan=0;
+        for (i=0; i < nsections; i++) {
+            exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
+            exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
+            exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
+            exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
+            exe_sections[i].chr = EC32(section_hdr[i].Characteristics);
+            exe_sections[i].urva = EC32(section_hdr[i].VirtualAddress); /* Just in case */
+            exe_sections[i].uvsz = EC32(section_hdr[i].VirtualSize);
+            exe_sections[i].uraw = EC32(section_hdr[i].PointerToRawData);
+            exe_sections[i].ursz = EC32(section_hdr[i].SizeOfRawData);
+
+            if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
+                if (!CLI_ISCONTAINED(0, fsize, exe_sections[i].uraw, exe_sections[i].ursz)
+                    || exe_sections[i].raw >= fsize) {
+                    cli_dbgmsg("Broken PE file - Section %d starts or exists beyond the end of file (Offset@ %lu, Total filesize %lu)\n", i, (unsigned long)exe_sections[i].raw, (unsigned long)fsize);
+                    if (nsections == 1) {
+                        free(section_hdr);
+                        free(exe_sections);
+
+                        if(DETECT_BROKEN_PE) {
+                            cli_append_virus(ctx, "Heuristics.Broken.Executable");
+                            return CL_VIRUS;
+                        }
+
+                        return CL_CLEAN; /* no ninjas to see here! move along! */
+                    }
+
+                    for (j=i; j < nsections-1; j++)
+                        memcpy(&exe_sections[j], &exe_sections[j+1], sizeof(struct cli_exe_section));
+
+                    for (j=i; j < nsections-1; j++)
+                        memcpy(&section_hdr[j], &section_hdr[j+1], sizeof(struct pe_image_section_hdr));
+
+                    nsections--;
+                    rescan=1;
+                    break;
+                }
+            }
+        }
+    }
+
     for(i = 0; i < nsections; i++) {
-	strncpy(sname, (char *) section_hdr[i].Name, 8);
-	sname[8] = 0;
-	exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
-	exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
-	exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
-	exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
-	exe_sections[i].chr = EC32(section_hdr[i].Characteristics);
-	exe_sections[i].urva = EC32(section_hdr[i].VirtualAddress); /* Just in case */
-	exe_sections[i].uvsz = EC32(section_hdr[i].VirtualSize);
-	exe_sections[i].uraw = EC32(section_hdr[i].PointerToRawData);
-	exe_sections[i].ursz = EC32(section_hdr[i].SizeOfRawData);
+        strncpy(sname, (char *) section_hdr[i].Name, 8);
+        sname[8] = 0;
 
 #if HAVE_JSON
         add_section_info(ctx, &exe_sections[i]);
@@ -1304,18 +1338,6 @@
 	}
 
 	if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
-	    if (exe_sections[i].raw >= fsize) { /* really broken */
-	      cli_dbgmsg("Broken PE file - Section %d starts beyond the end of file (Offset@ %lu, Total filesize %lu)\n", i, (unsigned long)exe_sections[i].raw, (unsigned long)fsize);
-	      cli_dbgmsg("------------------------------------\n");
-		free(section_hdr);
-		free(exe_sections);
-		if(DETECT_BROKEN_PE) {
-		    cli_append_virus(ctx, "Heuristics.Broken.Executable");
-		    return CL_VIRUS;
-		}
-		return CL_CLEAN; /* no ninjas to see here! move along! */
-	    }
-
 	    if(SCAN_ALGO && (DCONF & PE_CONF_POLIPOS) && !*sname && exe_sections[i].vsz > 40000 && exe_sections[i].vsz < 70000 && exe_sections[i].chr == 0xe0000060) polipos = i;
 
 	    /* check hash section sigs */
```
