# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1019_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1019_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/*! @file GPMF_parser.c
 * 
 *  @brief GPMF Parser library
 *
 *  @version 1.2.1
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
  * 
  *  @brief GPMF Parser library
  *
- *  @version 1.2.1
+ *  @version 1.2.2
  * 
  *  (C) Copyright 2017 GoPro Inc (http://gopro.com/).
  *	
@@ -42,7 +42,7 @@
 {
 	if (ms)
 	{
-		int32_t nestsize = (int32_t)ms->nest_size[ms->nest_level];
+		uint32_t nestsize = (uint32_t)ms->nest_size[ms->nest_level];
 		if (nestsize == 0 && ms->nest_level == 0)
 			nestsize = ms->buffer_size_longs;
 
```
