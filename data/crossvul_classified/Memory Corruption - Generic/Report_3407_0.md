# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3407_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3407_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 18-58 of the vulnerable file.

	char *input, *oinput, *ptr, *ptr2;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	RFSPlugin *plug;
	RFSPartition *part;
	RCore *core = (RCore *)data;

	if (!strncmp ("kdir", _input, 4)) {
		return cmd_mkdir (data, _input);
	}
	if (!strncmp ("v", _input, 1)) {
		return cmd_mv (data, _input);
	}
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ':
		input++;
		if (input[0]==' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr++;
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = r_num_math (core->num, ptr2+1);
			}
			if (!r_fs_mount (core->fs, ptr, input, off))
				eprintf ("Cannot mount %s\n", input);
		} else {
			if (!(ptr = r_fs_name (core->fs, core->offset)))
				eprintf ("Unknown filesystem type\n");
			else if (!r_fs_mount (core->fs, ptr, input, core->offset))
				eprintf ("Cannot mount %s\n", input);
			free (ptr);
		}
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,8 +35,9 @@
 	switch (*input) {
 	case ' ':
 		input++;
-		if (input[0]==' ')
-			input++;
+		if (input[0]==' ') {
+			input++;
+		}
 		ptr = strchr (input, ' ');
 		if (ptr) {
 			*ptr = 0;
@@ -46,13 +47,15 @@
 				*ptr2 = 0;
 				off = r_num_math (core->num, ptr2+1);
 			}
-			if (!r_fs_mount (core->fs, ptr, input, off))
+			if (!r_fs_mount (core->fs, ptr, input, off)) {
 				eprintf ("Cannot mount %s\n", input);
+			}
 		} else {
-			if (!(ptr = r_fs_name (core->fs, core->offset)))
+			if (!(ptr = r_fs_name (core->fs, core->offset))) {
 				eprintf ("Unknown filesystem type\n");
-			else if (!r_fs_mount (core->fs, ptr, input, core->offset))
+			} else if (!r_fs_mount (core->fs, ptr, input, core->offset)) {
 				eprintf ("Cannot mount %s\n", input);
+			}
 			free (ptr);
 		}
 		break;
```
