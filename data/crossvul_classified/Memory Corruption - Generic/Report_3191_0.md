# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3191_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3191_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 272-312 of the vulnerable file.


    return node_create(NULL, data);
}

static plist_t parse_date_node(const char **bnode, uint8_t size)
{
    plist_t node = parse_real_node(bnode, size);
    plist_data_t data = plist_get_data(node);

    data->type = PLIST_DATE;

    return node;
}

static plist_t parse_string_node(const char **bnode, uint64_t size)
{
    plist_data_t data = plist_new_plist_data();

    data->type = PLIST_STRING;
    data->strval = (char *) malloc(sizeof(char) * (size + 1));
    memcpy(data->strval, *bnode, size);
    data->strval[size] = '\0';
    data->length = strlen(data->strval);

    return node_create(NULL, data);
}

static char *plist_utf16_to_utf8(uint16_t *unistr, long len, long *items_read, long *items_written)
{
	if (!unistr || (len <= 0)) return NULL;
	char *outbuf = (char*)malloc(4*(len+1));
	int p = 0;
	long i = 0;

	uint16_t wc;
	uint32_t w;
	int read_lead_surrogate = 0; 

	while (i < len) {
		wc = unistr[i++];
		if (wc >= 0xD800 && wc <= 0xDBFF) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -289,6 +289,11 @@
 
     data->type = PLIST_STRING;
     data->strval = (char *) malloc(sizeof(char) * (size + 1));
+    if (!data->strval) {
+        plist_free_data(data);
+        PLIST_BIN_ERR("%s: Could not allocate %" PRIu64 " bytes\n", __func__, sizeof(char) * (size + 1));
+        return NULL;
+    }
     memcpy(data->strval, *bnode, size);
     data->strval[size] = '\0';
     data->length = strlen(data->strval);
```
