# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2415_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2415_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

				       fibh.ebh->b_data, poffset);
			}
		}

		if ((cfi.fileCharacteristics & FID_FILE_CHAR_DELETED) != 0) {
			if (!UDF_QUERY_FLAG(dir->i_sb, UDF_FLAG_UNDELETE))
				continue;
		}

		if ((cfi.fileCharacteristics & FID_FILE_CHAR_HIDDEN) != 0) {
			if (!UDF_QUERY_FLAG(dir->i_sb, UDF_FLAG_UNHIDE))
				continue;
		}

		if (cfi.fileCharacteristics & FID_FILE_CHAR_PARENT) {
			if (!dir_emit_dotdot(file, ctx))
				goto out;
			continue;
		}

		flen = udf_get_filename(dir->i_sb, nameptr, fname, lfi);
		if (!flen)
			continue;

		tloc = lelb_to_cpu(cfi.icb.extLocation);
		iblock = udf_get_lb_pblock(dir->i_sb, &tloc, 0);
		if (!dir_emit(ctx, fname, flen, iblock, DT_UNKNOWN))
			goto out;
	} /* end while */

	ctx->pos = (nf_pos >> 2) + 1;

out:
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	brelse(epos.bh);
	kfree(fname);

	return ret;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,7 +167,8 @@
 			continue;
 		}
 
-		flen = udf_get_filename(dir->i_sb, nameptr, fname, lfi);
+		flen = udf_get_filename(dir->i_sb, nameptr, lfi, fname,
+					UDF_NAME_LEN);
 		if (!flen)
 			continue;
 
```
