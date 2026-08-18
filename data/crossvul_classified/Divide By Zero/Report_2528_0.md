# CrossVul Fix Pair: Divide By Zero in cpp
**Pair ID:** 2528_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2528_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```cpp
Lines 1-22 of the vulnerable file.

// JPEGsnoop - JPEG Image Decoder & Analysis Utility
// Copyright (C) 2015 - Calvin Hass
// http://www.impulseadventure.com/photo/jpeg-snoop.html
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
//



#include "stdafx.h"

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 // JPEGsnoop - JPEG Image Decoder & Analysis Utility
-// Copyright (C) 2015 - Calvin Hass
+// Copyright (C) 2017 - Calvin Hass
 // http://www.impulseadventure.com/photo/jpeg-snoop.html
 //
 //    This program is free software: you can redistribute it and/or modify
@@ -4903,8 +4903,8 @@
 			// possibility of div by 0).
 			m_anSofHorzSampFact_Hi[nCompIdent] = (anSofSampFact[nCompIdent] & 0xF0) >> 4;	// Hi, range 1..4
 			m_anSofVertSampFact_Vi[nCompIdent] = (anSofSampFact[nCompIdent] & 0x0F);		// Vi, range 1..4
-			//if (!ValidateValue(m_anSofHorzSampFact_Hi[nCompIdent],1,4,_T("Horizontal Sampling Factor <Hi>"),true,1)) return DECMARK_ERR;
-			//if (!ValidateValue(m_anSofVertSampFact_Vi[nCompIdent],1,4,_T("Vertical Sampling Factor <Vi>"),true,1)) return DECMARK_ERR;
+			if (!ValidateValue(m_anSofHorzSampFact_Hi[nCompIdent],1,4,_T("Horizontal Sampling Factor <Hi>"),true,1)) return DECMARK_ERR;
+			if (!ValidateValue(m_anSofVertSampFact_Vi[nCompIdent],1,4,_T("Vertical Sampling Factor <Vi>"),true,1)) return DECMARK_ERR;
 
 		}
 
```
