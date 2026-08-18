# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 655_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `655_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-41 of the vulnerable file.

/* foreign file formats base class
 *
 * 7/2/12
 * 	- add support for sequential reads
 * 18/6/12
 * 	- flatten alpha with vips_flatten()
 * 28/5/13
 * 	- auto rshift down to 8 bits during save
 * 19/1/14
 * 	- pack and unpack rad to scrgb
 * 18/8/14
 * 	- fix conversion to 16-bit RGB, thanks John
 * 18/6/15
 * 	- forward progress signals from load
 * 23/5/16
 * 	- remove max-alpha stuff, this is now automatic
 * 12/6/17
 * 	- transform cmyk->rgb if there's an embedded profile
 * 16/6/17
 * 	- add page_height
 */

/*

    This file is part of VIPS.

    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,8 @@
  * 	- transform cmyk->rgb if there's an embedded profile
  * 16/6/17
  * 	- add page_height
+ * 5/3/18
+ * 	- block _start if one start fails, see #893
  */
 
 /*
@@ -796,6 +798,11 @@
 	VipsForeignLoad *load = VIPS_FOREIGN_LOAD( b );
 	VipsForeignLoadClass *class = VIPS_FOREIGN_LOAD_GET_CLASS( load );
 
+	/* If this start has failed before in another thread, we can fail now.
+	 */
+	if( load->error )
+		return( NULL );
+
 	if( !load->real ) {
 		if( !(load->real = vips_foreign_load_temp( load )) )
 			return( NULL );
@@ -819,19 +826,25 @@
 		g_object_set_qdata( G_OBJECT( load->real ), 
 			vips__foreign_load_operation, load ); 
 
-		if( class->load( load ) ||
-			vips_image_pio_input( load->real ) ) 
-			return( NULL );
-
-		/* ->header() read the header into @out, load has read the
+		/* Load the image and check the result.
+		 *
+		 * ->header() read the header into @out, load has read the
 		 * image into @real. They must match exactly in size, bands,
 		 * format and coding for the copy to work.  
 		 *
 		 * Some versions of ImageMagick give different results between
 		 * Ping and Load for some formats, for example.
+		 *
+		 * If the load fails, we need to stop
 		 */
-		if( !vips_foreign_load_iscompat( load->real, out ) )
+		if( class->load( load ) ||
+			vips_image_pio_input( load->real ) || 
+			vips_foreign_load_iscompat( load->real, out ) ) {
+			vips_operation_invalidate( VIPS_OPERATION( load ) ); 
+			load->error = TRUE;
+
 			return( NULL );
+		}
 
 		/* We have to tell vips that out depends on real. We've set
 		 * the demand hint below, but not given an input there.
```
