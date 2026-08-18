# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2384_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2384_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 500-540 of the vulnerable file.

	{	psf_log_printf (psf, "Error : This does not look like a MacOSX resource fork.\n") ;
		error = SFE_SD2_BAD_RSRC ;
		goto parse_rsrc_fork_cleanup ;
		} ;

	if (rsrc.map_offset + 28 >= rsrc.rsrc_len)
	{	psf_log_printf (psf, "Bad map offset (%d + 28 > %d).\n", rsrc.map_offset, rsrc.rsrc_len) ;
		error = SFE_SD2_BAD_RSRC ;
		goto parse_rsrc_fork_cleanup ;
		} ;

	rsrc.string_offset = rsrc.map_offset + read_rsrc_short (&rsrc, rsrc.map_offset + 26) ;
	if (rsrc.string_offset > rsrc.rsrc_len)
	{	psf_log_printf (psf, "Bad string offset (%d).\n", rsrc.string_offset) ;
		error = SFE_SD2_BAD_RSRC ;
		goto parse_rsrc_fork_cleanup ;
		} ;

	rsrc.type_offset = rsrc.map_offset + 30 ;

	rsrc.type_count = read_rsrc_short (&rsrc, rsrc.map_offset + 28) + 1 ;
	if (rsrc.type_count < 1)
	{	psf_log_printf (psf, "Bad type count.\n") ;
		error = SFE_SD2_BAD_RSRC ;
		goto parse_rsrc_fork_cleanup ;
		} ;

	rsrc.item_offset = rsrc.type_offset + rsrc.type_count * 8 ;
	if (rsrc.item_offset < 0 || rsrc.item_offset > rsrc.rsrc_len)
	{	psf_log_printf (psf, "Bad item offset (%d).\n", rsrc.item_offset) ;
		error = SFE_SD2_BAD_RSRC ;
		goto parse_rsrc_fork_cleanup ;
		} ;

	rsrc.str_index = -1 ;
	for (k = 0 ; k < rsrc.type_count ; k ++)
	{	marker = read_rsrc_marker (&rsrc, rsrc.type_offset + k * 8) ;

		if (marker == STR_MARKER)
		{	rsrc.str_index = k ;
			rsrc.str_count = read_rsrc_short (&rsrc, rsrc.type_offset + k * 8 + 4) + 1 ;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -517,6 +517,11 @@
 
 	rsrc.type_offset = rsrc.map_offset + 30 ;
 
+	if (rsrc.map_offset + 28 > rsrc.rsrc_len)
+	{	psf_log_printf (psf, "Bad map offset.\n") ;
+		goto parse_rsrc_fork_cleanup ;
+		} ;
+
 	rsrc.type_count = read_rsrc_short (&rsrc, rsrc.map_offset + 28) + 1 ;
 	if (rsrc.type_count < 1)
 	{	psf_log_printf (psf, "Bad type count.\n") ;
@@ -533,7 +538,12 @@
 
 	rsrc.str_index = -1 ;
 	for (k = 0 ; k < rsrc.type_count ; k ++)
-	{	marker = read_rsrc_marker (&rsrc, rsrc.type_offset + k * 8) ;
+	{	if (rsrc.type_offset + k * 8 > rsrc.rsrc_len)
+		{	psf_log_printf (psf, "Bad rsrc marker.\n") ;
+			goto parse_rsrc_fork_cleanup ;
+			} ;
+
+		marker = read_rsrc_marker (&rsrc, rsrc.type_offset + k * 8) ;
 
 		if (marker == STR_MARKER)
 		{	rsrc.str_index = k ;
```
