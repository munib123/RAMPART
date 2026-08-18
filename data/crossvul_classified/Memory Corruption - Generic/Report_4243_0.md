# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4243_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4243_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 554-594 of the vulnerable file.

            
        //
        // 
        //
        
        Int64 chunk_start = position;
        for (size_t i = 0; i < total_chunks ; i++)
        {
            //
            // do we have a part number?
            //
            
            int partNumber = 0;
            if(isMultiPart(version))
            {
                OPENEXR_IMF_INTERNAL_NAMESPACE::Xdr::read <OPENEXR_IMF_INTERNAL_NAMESPACE::StreamIO> (is, partNumber);
            }
            
            
            
            if(partNumber<0 || partNumber> static_cast<int>(parts.size()))
            {
                throw IEX_NAMESPACE::IoExc("part number out of range");
            }
            
            Header& header = parts[partNumber]->header;

            // size of chunk NOT including multipart field
            
            Int64 size_of_chunk=0;

            if (isTiled(header.type()))
            {
                //
                // 
                //
                int tilex,tiley,levelx,levely;
                OPENEXR_IMF_INTERNAL_NAMESPACE::Xdr::read <OPENEXR_IMF_INTERNAL_NAMESPACE::StreamIO> (is, tilex);
                OPENEXR_IMF_INTERNAL_NAMESPACE::Xdr::read <OPENEXR_IMF_INTERNAL_NAMESPACE::StreamIO> (is, tiley);
                OPENEXR_IMF_INTERNAL_NAMESPACE::Xdr::read <OPENEXR_IMF_INTERNAL_NAMESPACE::StreamIO> (is, levelx);
                OPENEXR_IMF_INTERNAL_NAMESPACE::Xdr::read <OPENEXR_IMF_INTERNAL_NAMESPACE::StreamIO> (is, levely);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -571,7 +571,7 @@
             
             
             
-            if(partNumber<0 || partNumber> static_cast<int>(parts.size()))
+            if(partNumber<0 || partNumber>= static_cast<int>(parts.size()))
             {
                 throw IEX_NAMESPACE::IoExc("part number out of range");
             }
```
