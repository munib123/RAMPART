# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 674_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `674_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 7-30 of the vulnerable file.

 * Copyright 2016 Thincast Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_LIB_CODEC_NSC_ENCODE_H
#define FREERDP_LIB_CODEC_NSC_ENCODE_H

#include <freerdp/api.h>

FREERDP_LOCAL void nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata,
                              UINT32 rowstride);

#endif /* FREERDP_LIB_CODEC_NSC_ENCODE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
 
 #include <freerdp/api.h>
 
-FREERDP_LOCAL void nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata,
+FREERDP_LOCAL BOOL nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata,
                               UINT32 rowstride);
 
 #endif /* FREERDP_LIB_CODEC_NSC_ENCODE_H */
```
