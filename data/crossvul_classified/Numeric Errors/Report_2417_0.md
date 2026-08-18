# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2417_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2417_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
** Copyright (C) 2002-2013 Erik de Castro Lopo <erikd@mega-nerd.com>
** Copyright (C) 2003 Ross Bencina <rbencina@iprimus.com.au>
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

/*
**	The file is split into three sections as follows:
**		- The top section (USE_WINDOWS_API == 0) for Linux, Unix and MacOSX
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
-** Copyright (C) 2002-2013 Erik de Castro Lopo <erikd@mega-nerd.com>
+** Copyright (C) 2002-2014 Erik de Castro Lopo <erikd@mega-nerd.com>
 ** Copyright (C) 2003 Ross Bencina <rbencina@iprimus.com.au>
 **
 ** This program is free software; you can redistribute it and/or modify
@@ -357,6 +357,9 @@
 psf_fwrite (const void *ptr, sf_count_t bytes, sf_count_t items, SF_PRIVATE *psf)
 {	sf_count_t total = 0 ;
 	ssize_t	count ;
+
+	if (bytes == 0 || items == 0)
+		return 0 ;
 
 	if (psf->virtual_io)
 		return psf->vio.write (ptr, bytes*items, psf->vio_user_data) / bytes ;
```
