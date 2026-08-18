# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1338_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1338_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 165-194 of the vulnerable file.

	struct DATAOBJECT dataobject;
};

int superblockRead(struct READER *reader, struct SUPERBLOCK *superblock);
void superblockFree(struct READER *reader, struct SUPERBLOCK *superblock);

int gcolRead(struct READER *reader, uint64_t gcol, int reference,
		uint64_t *dataobject);
void gcolFree(struct GCOL *gcol);

int treeRead(struct READER *reader, struct DATAOBJECT *data);

struct READER {
	FILE *fhd;

	struct DATAOBJECT *all;

	struct SUPERBLOCK superblock;

	struct GCOL *gcol;
};

int validAddress(struct READER *reader, uint64_t address);
uint64_t readValue(struct READER *reader, int size);

int gunzip(int inlen, char *in, int *outlen, char *out);

char *mysofa_strdup(const char *s);

#endif /* READER_H_ */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,8 @@
 	struct SUPERBLOCK superblock;
 
 	struct GCOL *gcol;
+
+	int recursive_counter;
 };
 
 int validAddress(struct READER *reader, uint64_t address);
```
