# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.


   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "rdesktop.h"


/* Parse an ASN.1 BER header */
RD_BOOL
ber_parse_header(STREAM s, int tagval, int *length)
{
	int tag, len;

	if (tagval > 0xff)
	{
		in_uint16_be(s, tag);
	}
	else
	{
		in_uint8(s, tag);
	}

	if (tag != tagval)
	{
		logger(Core, Error, "ber_parse_header(), expected tag %d, got %d", tagval, tag);
		return False;
	}

	in_uint8(s, len);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
 
 /* Parse an ASN.1 BER header */
 RD_BOOL
-ber_parse_header(STREAM s, int tagval, int *length)
+ber_parse_header(STREAM s, int tagval, uint32 *length)
 {
 	int tag, len;
 
```
