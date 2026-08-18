# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1376_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1376_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 6-46 of the vulnerable file.

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

#ifndef _THRIFT_PROTOCOL_TPROTOCOLEXCEPTION_H_
#define _THRIFT_PROTOCOL_TPROTOCOLEXCEPTION_H_ 1

#include <thrift/lib/cpp/Thrift.h>

#include <string>

namespace apache { namespace thrift { namespace protocol {

/**
 * Class to encapsulate all the possible types of protocol errors that may
 * occur in various protocol systems. This provides a sort of generic
 * wrapper around the shitty UNIX E_ error codes that lets a common code
 * base of error handling to be used for various types of protocols, i.e.
 * pipes etc.
 *
 */
class TProtocolException : public apache::thrift::TLibraryException {
 public:

  /**
   * Error codes for the various types of exceptions.
   */
  enum TProtocolExceptionType
  { UNKNOWN = 0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 #define _THRIFT_PROTOCOL_TPROTOCOLEXCEPTION_H_ 1
 
 #include <thrift/lib/cpp/Thrift.h>
+#include <thrift/lib/cpp/protocol/TType.h>
 
 #include <string>
 
@@ -106,6 +107,7 @@
       folly::StringPiece field,
       folly::StringPiece type);
   [[noreturn]] static void throwBoolValueOutOfRange(uint8_t value);
+  [[noreturn]] static void throwInvalidSkipType(TType type);
 
  protected:
   /**
```
