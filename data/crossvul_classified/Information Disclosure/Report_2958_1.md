# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2958_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2958_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 699-739 of the vulnerable file.

#ifdef FEAT_QUICKFIX
    if (!bt_dontwrite(curbuf))
#endif
    {
	check_need_swap(newfile);
#ifdef FEAT_AUTOCMD
	if (!read_stdin && (curbuf != old_curbuf
		|| (using_b_ffname && (old_b_ffname != curbuf->b_ffname))
		|| (using_b_fname && (old_b_fname != curbuf->b_fname))))
	{
	    EMSG(_(e_auchangedbuf));
	    if (!read_buffer)
		close(fd);
	    return FAIL;
	}
#endif
#ifdef UNIX
	/* Set swap file protection bits after creating it. */
	if (swap_mode > 0 && curbuf->b_ml.ml_mfp != NULL
			  && curbuf->b_ml.ml_mfp->mf_fname != NULL)
	    (void)mch_setperm(curbuf->b_ml.ml_mfp->mf_fname, (long)swap_mode);
#endif
    }

#if defined(HAS_SWAP_EXISTS_ACTION)
    /* If "Quit" selected at ATTENTION dialog, don't load the file */
    if (swap_exists_action == SEA_QUIT)
    {
	if (!read_buffer && !read_stdin)
	    close(fd);
	return FAIL;
    }
#endif

    ++no_wait_return;	    /* don't wait for return yet */

    /*
     * Set '[ mark to the line above where the lines go (line 1 if zero).
     */
    curbuf->b_op_start.lnum = ((from == 0) ? 1 : from);
    curbuf->b_op_start.col = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -716,7 +716,29 @@
 	/* Set swap file protection bits after creating it. */
 	if (swap_mode > 0 && curbuf->b_ml.ml_mfp != NULL
 			  && curbuf->b_ml.ml_mfp->mf_fname != NULL)
-	    (void)mch_setperm(curbuf->b_ml.ml_mfp->mf_fname, (long)swap_mode);
+	{
+	    char_u *swap_fname = curbuf->b_ml.ml_mfp->mf_fname;
+
+	    /*
+	     * If the group-read bit is set but not the world-read bit, then
+	     * the group must be equal to the group of the original file.  If
+	     * we can't make that happen then reset the group-read bit.  This
+	     * avoids making the swap file readable to more users when the
+	     * primary group of the user is too permissive.
+	     */
+	    if ((swap_mode & 044) == 040)
+	    {
+		stat_T	swap_st;
+
+		if (mch_stat((char *)swap_fname, &swap_st) >= 0
+			&& st.st_gid != swap_st.st_gid
+			&& fchown(curbuf->b_ml.ml_mfp->mf_fd, -1, st.st_gid)
+									 == -1)
+		    swap_mode &= 0600;
+	    }
+
+	    (void)mch_setperm(swap_fname, (long)swap_mode);
+	}
 #endif
     }
 
```
