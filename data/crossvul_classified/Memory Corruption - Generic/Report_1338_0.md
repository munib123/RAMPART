# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1338_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1338_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 16-56 of the vulnerable file.

static int log2i(int a) {
	return round(log2(a));
}

static int directblockRead(struct READER *reader, struct DATAOBJECT *dataobject,
		struct FRACTALHEAP *fractalheap) {

	char buf[4], *name, *value;
	int size, offset_size, length_size, err, len;
	uint8_t typeandversion;
	uint64_t unknown, heap_header_address, block_offset, block_size, offset,
			length;
	long store;
	struct DIR *dir;
	struct MYSOFA_ATTRIBUTE *attr;

	UNUSED(offset);
	UNUSED(block_size);
	UNUSED(block_offset);

	/* read signature */
	if (fread(buf, 1, 4, reader->fhd) != 4 || strncmp(buf, "FHDB", 4)) {
		log("cannot read signature of fractal heap indirect block\n");
		return MYSOFA_INVALID_FORMAT;
	}
	log("%08" PRIX64 " %.4s\n", (uint64_t )ftell(reader->fhd) - 4, buf);

	if (fgetc(reader->fhd) != 0) {
		log("object FHDB must have version 0\n");
		return MYSOFA_UNSUPPORTED_FORMAT;
	}

	/* ignore heap_header_address */
	if (fseek(reader->fhd, reader->superblock.size_of_offsets, SEEK_CUR) < 0)
		return errno;

	size = (fractalheap->maximum_heap_size + 7) / 8;
	block_offset = readValue(reader, size);

	if (fractalheap->flags & 2)
		if (fseek(reader->fhd, 4, SEEK_CUR))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,12 +33,17 @@
 	UNUSED(block_size);
 	UNUSED(block_offset);
 
+	if(reader->recursive_counter >= 10)
+		return MYSOFA_INVALID_FORMAT;
+	else
+		reader->recursive_counter++;
+
 	/* read signature */
 	if (fread(buf, 1, 4, reader->fhd) != 4 || strncmp(buf, "FHDB", 4)) {
 		log("cannot read signature of fractal heap indirect block\n");
 		return MYSOFA_INVALID_FORMAT;
 	}
-	log("%08" PRIX64 " %.4s\n", (uint64_t )ftell(reader->fhd) - 4, buf);
+	log("%08" PRIX64 " %.4s stack %d\n", (uint64_t )ftell(reader->fhd) - 4, buf, reader->recursive_counter);
 
 	if (fgetc(reader->fhd) != 0) {
 		log("object FHDB must have version 0\n");
@@ -218,6 +223,7 @@
 
 	} while (typeandversion != 0);
 
+	reader->recursive_counter--;
 	return MYSOFA_OK;
 }
 
```
