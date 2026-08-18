# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 963_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `963_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 461-501 of the vulnerable file.

          //  1 : same level
          //  + : further parent
          if (Result->ValidateSize() && (SizeFound == SizeUnknown || UpperLevel > 0 || MaxDataSize == 0 || MaxDataSize >= (PossibleID_Length + PossibleSizeLength + SizeFound))) {
            if (SizeFound != SizeUnknown || Result->SetSizeInfinite()) {
              Result->SizePosition = DataStream.getFilePointer() - SizeIdx + EBML_ID_LENGTH(PossibleID);
              Result->ElementPosition = Result->SizePosition - EBML_ID_LENGTH(PossibleID);
              // place the file at the beggining of the data
              DataStream.setFilePointer(Result->SizePosition + _SizeLength);
              return Result;
            }
          }
        }
        delete Result;
      }
    }

    // recover all the data in the buffer minus one byte
    ReadIndex = SizeIdx - 1;
    memmove(&PossibleIdNSize[0], &PossibleIdNSize[1], ReadIndex);
    UpperLevel = UpperLevel_original;
  } while ( MaxDataSize > DataStream.getFilePointer() - SizeIdx + PossibleID_Length );

  return NULL;
}

/*!
  \todo what happens if we are in a upper element with a known size ?
*/
EbmlElement * EbmlElement::SkipData(EbmlStream & DataStream, const EbmlSemanticContext & Context, EbmlElement * TestReadElt, bool AllowDummyElt)
{
  EbmlElement * Result = NULL;
  if (bSizeIsFinite) {
    assert(TestReadElt == NULL);
    assert(ElementPosition < SizePosition);
    DataStream.I_O().setFilePointer(SizePosition + CodedSizeLength(Size, SizeLength, bSizeIsFinite) + Size, seek_beginning);
    //    DataStream.I_O().setFilePointer(Size, seek_current);
  } else {
    /////////////////////////////////////////////////
    // read elements until an upper element is found
    /////////////////////////////////////////////////
    bool bEndFound = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -478,7 +478,7 @@
     ReadIndex = SizeIdx - 1;
     memmove(&PossibleIdNSize[0], &PossibleIdNSize[1], ReadIndex);
     UpperLevel = UpperLevel_original;
-  } while ( MaxDataSize > DataStream.getFilePointer() - SizeIdx + PossibleID_Length );
+  } while ( MaxDataSize >= ReadSize );
 
   return NULL;
 }
```
