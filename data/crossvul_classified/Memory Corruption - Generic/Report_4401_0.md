# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4401_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4401_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 254-296 of the vulnerable file.

	if (rv != SC_SUCCESS) {
		sc_file_free(file);
		LOG_TEST_RET(ctx, rv, "Cannot select oberthur file to read");
	}

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT)
		sz = file->size;
	else
		sz = (file->record_length + 2) * file->record_count;

	*out = calloc(sz, 1);
	if (*out == NULL) {
		sc_file_free(file);
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot read oberthur file");
	}

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT)   {
		rv = sc_read_binary(card, 0, *out, sz, 0);
	}
	else	{
		int rec;
		int offs = 0;
		int rec_len = file->record_length;

		for (rec = 1; ; rec++)   {
			rv = sc_read_record(card, rec, *out + offs + 2, rec_len, SC_RECORD_BY_REC_NR);
			if (rv == SC_ERROR_RECORD_NOT_FOUND)   {
				rv = 0;
				break;
			}
			else if (rv < 0)   {
				break;
			}

			rec_len = rv;

			*(*out + offs) = 'R';
			*(*out + offs + 1) = rv;

			offs += rv + 2;
		}

		sz = offs;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -271,11 +271,15 @@
 		rv = sc_read_binary(card, 0, *out, sz, 0);
 	}
 	else	{
-		int rec;
-		int offs = 0;
-		int rec_len = file->record_length;
+		size_t rec;
+		size_t offs = 0;
+		size_t rec_len = file->record_length;
 
 		for (rec = 1; ; rec++)   {
+			if (rec > file->record_count) {
+				rv = 0;
+				break;
+			}
 			rv = sc_read_record(card, rec, *out + offs + 2, rec_len, SC_RECORD_BY_REC_NR);
 			if (rv == SC_ERROR_RECORD_NOT_FOUND)   {
 				rv = 0;
```
