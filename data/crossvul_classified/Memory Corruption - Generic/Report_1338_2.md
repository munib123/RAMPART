# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1338_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1338_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 227-267 of the vulnerable file.


MYSOFA_EXPORT struct MYSOFA_HRTF* mysofa_load(const char *filename, int *err) {
	struct READER reader;
	struct MYSOFA_HRTF *hrtf = NULL;

	if (filename == NULL)
		filename = CMAKE_INSTALL_PREFIX "/share/libmysofa/default.sofa";

	if (strcmp(filename, "-"))
		reader.fhd = fopen(filename, "rb");
	else
		reader.fhd = stdin;

	if (!reader.fhd) {
		log("cannot open file %s\n", filename);
		*err = errno;
		return NULL;
	}
	reader.gcol = NULL;
	reader.all = NULL;

	*err = superblockRead(&reader, &reader.superblock);

	if (!*err) {
		hrtf = getHrtf(&reader, err);
	}

	superblockFree(&reader, &reader.superblock);
	gcolFree(reader.gcol);
	if (strcmp(filename, "-"))
		fclose(reader.fhd);

	return hrtf;
}

static void arrayFree(struct MYSOFA_ARRAY *array) {
	while (array->attributes) {
		struct MYSOFA_ATTRIBUTE *next = array->attributes->next;
		free(array->attributes->name);
		free(array->attributes->value);
		free(array->attributes);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -244,6 +244,7 @@
 	}
 	reader.gcol = NULL;
 	reader.all = NULL;
+	reader.recursive_counter = 0;
 
 	*err = superblockRead(&reader, &reader.superblock);
 
```
