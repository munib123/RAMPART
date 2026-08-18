# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 1385_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1385_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 5-45 of the vulnerable file.

 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package thrift

import (
	"errors"
)

type ProtocolID int16

const (
	ProtocolIDBinary     ProtocolID = 0
	ProtocolIDJSON       ProtocolID = 1
	ProtocolIDCompact    ProtocolID = 2
	ProtocolIDDebug      ProtocolID = 3
	ProtocolIDVirtual    ProtocolID = 4
	ProtocolIDSimpleJSON ProtocolID = 5
)

func (p ProtocolID) String() string {
	switch p {
	case ProtocolIDBinary:
		return "binary"
	case ProtocolIDJSON:
		return "json"
	case ProtocolIDCompact:
		return "compact"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 
 import (
 	"errors"
+	"fmt"
 )
 
 type ProtocolID int16
@@ -127,8 +128,6 @@
 	}
 
 	switch fieldType {
-	case STOP:
-		return
 	case BOOL:
 		_, err = self.ReadBool()
 		return
@@ -206,6 +205,7 @@
 			}
 		}
 		return self.ReadListEnd()
+	default:
+		return fmt.Errorf("unable to skip over unknown type id %d", fieldType)
 	}
-	return nil
-}
+}
```
