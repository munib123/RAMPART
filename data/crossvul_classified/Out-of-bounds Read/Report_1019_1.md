# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1019_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1019_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/*! @file GPMF_parser.h
 * 
 *  @brief GPMF Parser library include
 * 
 *  @version 1.1.0
 * 
 *  (C) Copyright 2017 GoPro Inc (http://gopro.com/).
 *	
 *  Licensed under either:
 *  - Apache License, Version 2.0, http://www.apache.org/licenses/LICENSE-2.0  
 *  - MIT license, http://opensource.org/licenses/MIT
 *  at your option.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * 
 */

#ifndef _GPMF_PARSER_H
#define _GPMF_PARSER_H

#ifdef __cplusplus
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
  * 
  *  @brief GPMF Parser library include
  * 
- *  @version 1.1.0
+ *  @version 1.1.1
  * 
  *  (C) Copyright 2017 GoPro Inc (http://gopro.com/).
  *	
@@ -126,7 +126,11 @@
 	GPMF_KEY_UNITS =			MAKEID('U','N','I','T'),//UNIT - Freedform display string for metadata units (char sting like "RPM", "MPH", "km/h", etc)
 	GPMF_KEY_SCALE =			MAKEID('S','C','A','L'),//SCAL - divisor for input data to scale to the correct units.
 	GPMF_KEY_TYPE =				MAKEID('T','Y','P','E'),//TYPE - Type define for complex data structures
-	GPMF_KEY_TOTAL_SAMPLES =	MAKEID('T','S','M','P'),//TOTL - Total Sample Count including the current payload 	
+	GPMF_KEY_TOTAL_SAMPLES =	MAKEID('T','S','M','P'),//TSMP - Total Sample Count including the current payload 	
+	GPMF_KEY_TIME_OFFSET =		MAKEID('T','I','M','O'),//TIMO - Time offset of the metadata stream that follows (single 4 byte float)
+	GPMF_KEY_TIMING_OFFSET =	MAKEID('T','I','M','O'),//TIMO - duplicated, as older code might use the other version of TIMO
+	GPMF_KEY_TIME_STAMP =		MAKEID('S','T','M','P'),//STMP - Time stamp for the first sample. 
+	GPMF_KEY_TIME_STAMPS =		MAKEID('S','T','P','S'),//STPS - Stream of all the timestamps delivered (Generally don't use this. This would be if your sensor has no peroidic times, yet precision is required, or for debugging.) 
 	GPMF_KEY_TICK =				MAKEID('T','I','C','K'),//TICK - Used for slow data. Beginning of data timing in milliseconds. 
 	GPMF_KEY_TOCK =				MAKEID('T','O','C','K'),//TOCK - Used for slow data. End of data timing in milliseconds. 
 	GPMF_KEY_EMPTY_PAYLOADS =	MAKEID('E','M','P','T'),//EMPT - Payloads that are empty since the device start (e.g. BLE disconnect.)
```
