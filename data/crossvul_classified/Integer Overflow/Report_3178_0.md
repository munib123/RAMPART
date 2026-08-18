# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3178_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3178_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1770-1810 of the vulnerable file.

	vim_free(file_name);
}

/*
 * Load the undo tree from an undo file.
 * If "name" is not NULL use it as the undo file name.  This also means being
 * a bit more verbose.
 * Otherwise use curbuf->b_ffname to generate the undo file name.
 * "hash[UNDO_HASH_SIZE]" must be the hash value of the buffer text.
 */
    void
u_read_undo(char_u *name, char_u *hash, char_u *orig_name)
{
    char_u	*file_name;
    FILE	*fp;
    long	version, str_len;
    char_u	*line_ptr = NULL;
    linenr_T	line_lnum;
    colnr_T	line_colnr;
    linenr_T	line_count;
    int		num_head = 0;
    long	old_header_seq, new_header_seq, cur_header_seq;
    long	seq_last, seq_cur;
    long	last_save_nr = 0;
    short	old_idx = -1, new_idx = -1, cur_idx = -1;
    long	num_read_uhps = 0;
    time_t	seq_time;
    int		i, j;
    int		c;
    u_header_T	*uhp;
    u_header_T	**uhp_table = NULL;
    char_u	read_hash[UNDO_HASH_SIZE];
    char_u	magic_buf[UF_START_MAGIC_LEN];
#ifdef U_DEBUG
    int		*uhp_table_used;
#endif
#ifdef UNIX
    stat_T	st_orig;
    stat_T	st_undo;
#endif
    bufinfo_T	bi;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1787,7 +1787,7 @@
     linenr_T	line_lnum;
     colnr_T	line_colnr;
     linenr_T	line_count;
-    int		num_head = 0;
+    long	num_head = 0;
     long	old_header_seq, new_header_seq, cur_header_seq;
     long	seq_last, seq_cur;
     long	last_save_nr = 0;
@@ -1974,7 +1974,8 @@
      * When there are no headers uhp_table is NULL. */
     if (num_head > 0)
     {
-	uhp_table = (u_header_T **)U_ALLOC_LINE(
+	if (num_head < LONG_MAX / (long)sizeof(u_header_T *))
+	    uhp_table = (u_header_T **)U_ALLOC_LINE(
 					     num_head * sizeof(u_header_T *));
 	if (uhp_table == NULL)
 	    goto error;
```
