# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3179_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3179_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1368-1408 of the vulnerable file.

    undo_write_bytes(bi, (long_u)uep->ue_top, 4);
    undo_write_bytes(bi, (long_u)uep->ue_bot, 4);
    undo_write_bytes(bi, (long_u)uep->ue_lcount, 4);
    undo_write_bytes(bi, (long_u)uep->ue_size, 4);
    for (i = 0; i < uep->ue_size; ++i)
    {
	len = STRLEN(uep->ue_array[i]);
	if (undo_write_bytes(bi, (long_u)len, 4) == FAIL)
	    return FAIL;
	if (len > 0 && fwrite_crypt(bi, uep->ue_array[i], len) == FAIL)
	    return FAIL;
    }
    return OK;
}

    static u_entry_T *
unserialize_uep(bufinfo_T *bi, int *error, char_u *file_name)
{
    int		i;
    u_entry_T	*uep;
    char_u	**array;
    char_u	*line;
    int		line_len;

    uep = (u_entry_T *)U_ALLOC_LINE(sizeof(u_entry_T));
    if (uep == NULL)
	return NULL;
    vim_memset(uep, 0, sizeof(u_entry_T));
#ifdef U_DEBUG
    uep->ue_magic = UE_MAGIC;
#endif
    uep->ue_top = undo_read_4c(bi);
    uep->ue_bot = undo_read_4c(bi);
    uep->ue_lcount = undo_read_4c(bi);
    uep->ue_size = undo_read_4c(bi);
    if (uep->ue_size > 0)
    {
	array = (char_u **)U_ALLOC_LINE(sizeof(char_u *) * uep->ue_size);
	if (array == NULL)
	{
	    *error = TRUE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1385,7 +1385,7 @@
 {
     int		i;
     u_entry_T	*uep;
-    char_u	**array;
+    char_u	**array = NULL;
     char_u	*line;
     int		line_len;
 
@@ -1402,7 +1402,8 @@
     uep->ue_size = undo_read_4c(bi);
     if (uep->ue_size > 0)
     {
-	array = (char_u **)U_ALLOC_LINE(sizeof(char_u *) * uep->ue_size);
+	if (uep->ue_size < LONG_MAX / (int)sizeof(char_u *))
+	    array = (char_u **)U_ALLOC_LINE(sizeof(char_u *) * uep->ue_size);
 	if (array == NULL)
 	{
 	    *error = TRUE;
@@ -1410,8 +1411,6 @@
 	}
 	vim_memset(array, 0, sizeof(char_u *) * uep->ue_size);
     }
-    else
-	array = NULL;
     uep->ue_array = array;
 
     for (i = 0; i < uep->ue_size; ++i)
```
