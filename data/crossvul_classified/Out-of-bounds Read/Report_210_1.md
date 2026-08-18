# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 210_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `210_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 615-655 of the vulnerable file.

	gf_free(ptr);
}


GF_Err urn_Read(GF_Box *s, GF_BitStream *bs)
{
	u32 i, to_read;
	char *tmpName;
	GF_DataEntryURNBox *ptr = (GF_DataEntryURNBox *)s;
	if (! ptr->size ) return GF_OK;

	//here we have to handle that in a clever way
	to_read = (u32) ptr->size;
	tmpName = (char*)gf_malloc(sizeof(char) * to_read);
	if (!tmpName) return GF_OUT_OF_MEM;
	//get the data
	gf_bs_read_data(bs, tmpName, to_read);

	//then get the break
	i = 0;
	while ( (tmpName[i] != 0) && (i < to_read) ) {
		i++;
	}
	//check the data is consistent
	if (i == to_read) {
		gf_free(tmpName);
		return GF_ISOM_INVALID_FILE;
	}
	//no NULL char, URL is not specified
	if (i == to_read - 1) {
		ptr->nameURN = tmpName;
		ptr->location = NULL;
		return GF_OK;
	}
	//OK, this has both URN and URL
	ptr->nameURN = (char*)gf_malloc(sizeof(char) * (i+1));
	if (!ptr->nameURN) {
		gf_free(tmpName);
		return GF_OUT_OF_MEM;
	}
	ptr->location = (char*)gf_malloc(sizeof(char) * (to_read - i - 1));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -632,7 +632,7 @@
 
 	//then get the break
 	i = 0;
-	while ( (tmpName[i] != 0) && (i < to_read) ) {
+	while ( (i < to_read) && (tmpName[i] != 0) ) {
 		i++;
 	}
 	//check the data is consistent
```
