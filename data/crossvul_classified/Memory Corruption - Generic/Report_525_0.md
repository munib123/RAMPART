# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 525_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `525_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2339-2379 of the vulnerable file.


	e = cat_isomedia_file(cat_enum->dest, szFileName, cat_enum->import_flags, cat_enum->force_fps, cat_enum->frames_per_sample, cat_enum->tmp_dir, cat_enum->force_cat, cat_enum->align_timelines, cat_enum->allow_add_in_command);
	if (e) return 1;
	return 0;
}

GF_Err cat_multiple_files(GF_ISOFile *dest, char *fileName, u32 import_flags, Double force_fps, u32 frames_per_sample, char *tmp_dir, Bool force_cat, Bool align_timelines, Bool allow_add_in_command)
{
	CATEnum cat_enum;
	char *sep;

	cat_enum.dest = dest;
	cat_enum.import_flags = import_flags;
	cat_enum.force_fps = force_fps;
	cat_enum.frames_per_sample = frames_per_sample;
	cat_enum.tmp_dir = tmp_dir;
	cat_enum.force_cat = force_cat;
	cat_enum.align_timelines = align_timelines;
	cat_enum.allow_add_in_command = allow_add_in_command;

	strcpy(cat_enum.szPath, fileName);
	sep = strrchr(cat_enum.szPath, GF_PATH_SEPARATOR);
	if (!sep) sep = strrchr(cat_enum.szPath, '/');
	if (!sep) {
		strcpy(cat_enum.szPath, ".");
		strcpy(cat_enum.szRad1, fileName);
	} else {
		strcpy(cat_enum.szRad1, sep+1);
		sep[0] = 0;
	}
	sep = strchr(cat_enum.szRad1, '*');
	strcpy(cat_enum.szRad2, sep+1);
	sep[0] = 0;
	sep = strchr(cat_enum.szRad2, '%');
	if (!sep) sep = strchr(cat_enum.szRad2, '#');
	if (!sep) sep = strchr(cat_enum.szRad2, ':');
	strcpy(cat_enum.szOpt, "");
	if (sep) {
		strcpy(cat_enum.szOpt, sep);
		sep[0] = 0;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2356,17 +2356,33 @@
 	cat_enum.align_timelines = align_timelines;
 	cat_enum.allow_add_in_command = allow_add_in_command;
 
+	if (strlen(fileName) >= sizeof(cat_enum.szPath)) {
+		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("File name %s is too long.\n", fileName));
+		return GF_NOT_SUPPORTED;
+	}
 	strcpy(cat_enum.szPath, fileName);
 	sep = strrchr(cat_enum.szPath, GF_PATH_SEPARATOR);
 	if (!sep) sep = strrchr(cat_enum.szPath, '/');
 	if (!sep) {
 		strcpy(cat_enum.szPath, ".");
+		if (strlen(fileName) >= sizeof(cat_enum.szRad1)) {
+			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("File name %s is too long.\n", fileName));
+			return GF_NOT_SUPPORTED;
+		}
 		strcpy(cat_enum.szRad1, fileName);
 	} else {
+		if (strlen(sep + 1) >= sizeof(cat_enum.szRad1)) {
+			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("File name %s is too long.\n", (sep + 1)));
+			return GF_NOT_SUPPORTED;
+		}
 		strcpy(cat_enum.szRad1, sep+1);
 		sep[0] = 0;
 	}
 	sep = strchr(cat_enum.szRad1, '*');
+	if (strlen(sep + 1) >= sizeof(cat_enum.szRad2)) {
+		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("File name %s is too long.\n", (sep + 1)));
+		return GF_NOT_SUPPORTED;
+	}
 	strcpy(cat_enum.szRad2, sep+1);
 	sep[0] = 0;
 	sep = strchr(cat_enum.szRad2, '%');
@@ -2374,6 +2390,10 @@
 	if (!sep) sep = strchr(cat_enum.szRad2, ':');
 	strcpy(cat_enum.szOpt, "");
 	if (sep) {
+		if (strlen(sep) >= sizeof(cat_enum.szOpt)) {
+			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("Invalid option: %s.\n", sep));
+			return GF_NOT_SUPPORTED;
+		}
 		strcpy(cat_enum.szOpt, sep);
 		sep[0] = 0;
 	}
```
