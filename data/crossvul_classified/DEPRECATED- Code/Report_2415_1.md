# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2415_1
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2415_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 216-256 of the vulnerable file.

			}
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_DELETED) != 0) {
			if (!UDF_QUERY_FLAG(dir->i_sb, UDF_FLAG_UNDELETE))
				continue;
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_HIDDEN) != 0) {
			if (!UDF_QUERY_FLAG(dir->i_sb, UDF_FLAG_UNHIDE))
				continue;
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_PARENT) &&
		    isdotdot)
			goto out_ok;

		if (!lfi)
			continue;

		flen = udf_get_filename(dir->i_sb, nameptr, fname, lfi);
		if (flen && udf_match(flen, fname, child->len, child->name))
			goto out_ok;
	}

out_err:
	fi = NULL;
	if (fibh->sbh != fibh->ebh)
		brelse(fibh->ebh);
	brelse(fibh->sbh);
out_ok:
	brelse(epos.bh);
	kfree(fname);

	return fi;
}

static struct dentry *udf_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct inode *inode = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,7 +233,8 @@
 		if (!lfi)
 			continue;
 
-		flen = udf_get_filename(dir->i_sb, nameptr, fname, lfi);
+		flen = udf_get_filename(dir->i_sb, nameptr, lfi, fname,
+					UDF_NAME_LEN);
 		if (flen && udf_match(flen, fname, child->len, child->name))
 			goto out_ok;
 	}
```
