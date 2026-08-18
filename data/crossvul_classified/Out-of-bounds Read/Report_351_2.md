# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 543-583 of the vulnerable file.

			rv = authentic_process_fci(card, file, resp, resplen);
			LOG_TEST_RET(ctx, rv, "cannot set 'current file': FCI process error");

			break;
		default:
			LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}

		if (file->type == SC_FILE_TYPE_DF)   {
			struct sc_path cur_df_path;

			memset(&cur_df_path, 0, sizeof(cur_df_path));
			if (card->cache.valid && card->cache.current_df)   {
				cur_df_path = card->cache.current_df->path;
				sc_file_free(card->cache.current_df);
			}
			card->cache.current_df = NULL;
			sc_file_dup(&card->cache.current_df, file);

			if (cur_df_path.len)   {
				memcpy(card->cache.current_df->path.value + cur_df_path.len,
						card->cache.current_df->path.value,
						card->cache.current_df->path.len);
				memcpy(card->cache.current_df->path.value, cur_df_path.value, cur_df_path.len);
				card->cache.current_df->path.len += cur_df_path.len;
			}

			sc_file_free(card->cache.current_ef);
			card->cache.current_ef = NULL;

			card->cache.valid = 1;
		}
		else   {
			sc_file_free(card->cache.current_ef);
			card->cache.current_ef = NULL;
			sc_file_dup(&card->cache.current_ef, file);
		}

		if (file_out)
			*file_out = file;
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -560,6 +560,9 @@
 			sc_file_dup(&card->cache.current_df, file);
 
 			if (cur_df_path.len)   {
+				if (cur_df_path.len + card->cache.current_df->path.len > sizeof card->cache.current_df->path.value
+						|| cur_df_path.len > sizeof card->cache.current_df->path.value)
+					LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
 				memcpy(card->cache.current_df->path.value + cur_df_path.len,
 						card->cache.current_df->path.value,
 						card->cache.current_df->path.len);
@@ -988,7 +991,7 @@
 	}
 
 	sc_log_hex(ctx, "ACL data", file->sec_attr, file->sec_attr_len);
-	for (ii = 0; ii < file->sec_attr_len / 2; ii++)  {
+	for (ii = 0; ii < file->sec_attr_len / 2 && ii < sizeof ops_DF; ii++)  {
 		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];
 		unsigned char acl = *(file->sec_attr + ii*2);
 		unsigned char cred_id = *(file->sec_attr + ii*2 + 1);
```
