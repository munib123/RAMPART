# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5509_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5509_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.

				if (last && s != s0)
					break;
				else
					return dir;
			}
			/* This is deliberately slash-only.  */
			if (*s == '/')
				break;
			s++;
		}

		dirname = g_strndup (s0, s - s0);
		while (*s == '/')
			s++;

		if (strcmp (dirname, ".") != 0) {
			GsfInput *subdir =
				gsf_infile_child_by_name (GSF_INFILE (dir),
							  dirname);
			if (subdir) {
				/* Undo the ref. */
				g_object_unref (subdir);
				dir = GSF_INFILE_TAR (subdir);
			} else
				dir = tar_create_dir (dir, dirname);
		}

		g_free (dirname);
	}
}


/*****************************************************************************/

/**
 * tar_init_info :
 * @tar : #GsfInfileTar
 *
 * Read tar headers and do some sanity checking
 * along the way.
 **/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,9 +181,11 @@
 				gsf_infile_child_by_name (GSF_INFILE (dir),
 							  dirname);
 			if (subdir) {
+				dir = GSF_IS_INFILE_TAR (subdir)
+					? GSF_INFILE_TAR (subdir)
+					: dir;
 				/* Undo the ref. */
 				g_object_unref (subdir);
-				dir = GSF_INFILE_TAR (subdir);
 			} else
 				dir = tar_create_dir (dir, dirname);
 		}
```
