# CrossVul Fix Pair: Use of Uninitialized Resource in c
**Pair ID:** 4262_0
**Vulnerability Class:** Use of Uninitialized Resource
**CWE:** CWE-908
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4262_0`)

## Vulnerability Information & PoC

## Description
Use of Uninitialized Resource - When a resource has not been properly initialized, the product may behave unexpectedly.

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

	int i;
	VipsForeignDzLayout layout = VIPS_FOREIGN_DZ_LAYOUT_DZ; 
	char *suffix = ".jpeg";
	int overlap = 0;
	int tile_size = 256;
	VipsForeignDzDepth depth = VIPS_FOREIGN_DZ_DEPTH_ONEPIXEL; 
	gboolean centre = FALSE;
	VipsAngle angle = VIPS_ANGLE_D0; 

	/* We can't use im_filename_split() --- it assumes that we have a
	 * filename with an extension before the ':', and filename here is
	 * actually a dirname.
	 *
	 * Just split on the first ':'.
	 */
	im_strncpy( name, filename, FILENAME_MAX ); 
	if( (p = strchr( name, ':' )) ) {
		*p = '\0';
		im_strncpy( mode, p + 1, FILENAME_MAX ); 
	}

	strcpy( buf, mode ); 
	p = &buf[0];

	if( (q = im_getnextoption( &p )) ) {
		if( (i = vips_enum_from_nick( "im_vips2dz", 
			VIPS_TYPE_FOREIGN_DZ_LAYOUT, q )) < 0 ) 
			return( -1 );
		layout = i;
	}

	if( (q = im_getnextoption( &p )) ) 
		suffix = g_strdup( q );
	if( (q = im_getnextoption( &p )) ) 
		overlap = atoi( q ); 
	if( (q = im_getnextoption( &p )) ) 
		tile_size = atoi( q ); 

	if( (q = im_getnextoption( &p )) ) {
		if( (i = vips_enum_from_nick( "im_vips2dz", 
			VIPS_TYPE_FOREIGN_DZ_DEPTH, q )) < 0 )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,8 @@
 		*p = '\0';
 		im_strncpy( mode, p + 1, FILENAME_MAX ); 
 	}
+	else 
+		strcpy( mode, "" ); 
 
 	strcpy( buf, mode ); 
 	p = &buf[0];
```
