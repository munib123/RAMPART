# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4947_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4947_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 333-373 of the vulnerable file.


	for (i = 0; i < data_len; ++i) {
		if (header->filename[i] == '\\') {
			header->filename[i] = '/';
		}
	}

	return split_header_filename(header);
}

// Read some more data from the input stream, extending the raw_data
// array (and the size of the header).

static uint8_t *extend_raw_data(LHAFileHeader **header,
                                LHAInputStream *stream,
                                size_t nbytes)
{
	LHAFileHeader *new_header;
	size_t new_raw_len;
	uint8_t *result;

	// Reallocate the header and raw_data area to be larger.

	new_raw_len = RAW_DATA_LEN(header) + nbytes;
	new_header = realloc(*header, sizeof(LHAFileHeader) + new_raw_len);

	if (new_header == NULL) {
		return NULL;
	}

	// Update the header pointer to point to the new area.

	*header = new_header;
	new_header->raw_data = (uint8_t *) (new_header + 1);
	result = new_header->raw_data + new_header->raw_data_len;

	// Read data from stream into new area.

	if (!lha_input_stream_read(stream, result, nbytes)) {
		return NULL;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -351,6 +351,10 @@
 	size_t new_raw_len;
 	uint8_t *result;
 
+	if (nbytes > LEVEL_3_MAX_HEADER_LEN) {
+		return NULL;
+	}
+
 	// Reallocate the header and raw_data area to be larger.
 
 	new_raw_len = RAW_DATA_LEN(header) + nbytes;
@@ -797,7 +801,8 @@
 
 	header_len = lha_decode_uint32(&RAW_DATA(header, 24));
 
-	if (header_len > LEVEL_3_MAX_HEADER_LEN) {
+	if (header_len > LEVEL_3_MAX_HEADER_LEN
+	 || header_len < RAW_DATA_LEN(header)) {
 		return 0;
 	}
 
```
