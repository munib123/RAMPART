# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 5388_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5388_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 1-32 of the vulnerable file.


/*
* BER Decoder
* (C) 1999-2008,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource* ber, ASN1_Tag& type_tag, ASN1_Tag& class_tag)
   {
   byte b;
   if(!ber->read_byte(b))
      {
      class_tag = type_tag = NO_OBJECT;
      return 0;
      }

   if((b & 0x1F) != 0x1F)
      {
      type_tag = ASN1_Tag(b & 0x1F);
      class_tag = ASN1_Tag(b & 0xE0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 #include <botan/ber_dec.h>
 #include <botan/bigint.h>
 #include <botan/loadstor.h>
+#include <botan/internal/safeint.h>
 
 namespace Botan {
 
@@ -126,7 +127,9 @@
       size_t item_size = decode_length(&source, length_size);
       source.discard_next(item_size);
 
-      length += item_size + length_size + tag_size;
+      length = BOTAN_CHECKED_ADD(length, item_size);
+      length = BOTAN_CHECKED_ADD(length, tag_size);
+      length = BOTAN_CHECKED_ADD(length, length_size);
 
       if(type_tag == EOC && class_tag == UNIVERSAL)
          break;
```
