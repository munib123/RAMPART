# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3288_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3288_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
** Copyright (C) 2010-2011 Erik de Castro Lopo <erikd@mega-nerd.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License as published by
** the Free Software Foundation; either version 2.1 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU Lesser General Public License for more details.
**
** You should have received a copy of the GNU Lesser General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include	"sfconfig.h"

#include	<stdio.h>
#include	<fcntl.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
-** Copyright (C) 2010-2011 Erik de Castro Lopo <erikd@mega-nerd.com>
+** Copyright (C) 2010-2017 Erik de Castro Lopo <erikd@mega-nerd.com>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU Lesser General Public License as published by
@@ -48,9 +48,11 @@
 
 		/* Calculate new file offset and position ourselves there. */
 		psf->fileoffset += offset + 10 ;
-		psf_binheader_readf (psf, "p", psf->fileoffset) ;
 
-		return 1 ;
+		if (psf->fileoffset < psf->filelength)
+		{	psf_binheader_readf (psf, "p", psf->fileoffset) ;
+			return 1 ;
+			} ;
 		} ;
 
 	return 0 ;
```
